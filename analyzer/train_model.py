import numpy as np
import pandas as pd
import joblib
import os
import urllib.request

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ==============================
# NSL-KDD Dataset Download
# ==============================

DATASET_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
)
DATASET_PATH = "KDDTrain+.txt"

NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

print("=" * 55)
print("  Traffic Intelligence — ML Model Trainer")
print("  Using NSL-KDD Network Intrusion Dataset")
print("=" * 55)

# ── Step 1: Download Dataset ──────────────────────────────
if not os.path.exists(DATASET_PATH):
    print(f"\n📥 Downloading NSL-KDD dataset...")
    try:
        urllib.request.urlretrieve(DATASET_URL, DATASET_PATH)
        print("✅ Dataset downloaded successfully!\n")
    except Exception as e:
        print(f"⚠️  Download failed ({e}). Using realistic synthetic fallback.\n")
        DATASET_PATH = None
else:
    print(f"\n✅ Dataset already present: {DATASET_PATH}\n")

# ── Step 2: Build Feature Matrix ──────────────────────────
#
# Feature mapping from NSL-KDD → our 6 packet-level features:
#   packet_count ← count (connection count to same host in 2s window)
#   total_bytes  ← src_bytes + dst_bytes
#   avg_size     ← total_bytes / max(count, 1)
#   duration     ← duration (in seconds)
#   byte_rate    ← total_bytes / max(duration, 0.001)
#   packet_rate  ← count / max(duration, 0.001)
#

if DATASET_PATH and os.path.exists(DATASET_PATH):
    print("📊 Loading NSL-KDD dataset...")
    df = pd.read_csv(DATASET_PATH, header=None, names=NSL_KDD_COLUMNS)
    print(f"   Rows loaded : {len(df):,}")
    print(f"   Normal flows: {(df['label'] == 'normal').sum():,}")
    print(f"   Attack flows: {(df['label'] != 'normal').sum():,}\n")

    # Cast numeric columns
    for col in ["duration", "src_bytes", "dst_bytes", "count",
                "srv_count", "dst_host_count"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    df["total_bytes"]  = df["src_bytes"] + df["dst_bytes"]
    df["avg_size"]     = df["total_bytes"] / df["count"].clip(lower=1)
    df["byte_rate"]    = df["total_bytes"] / df["duration"].clip(lower=0.001)
    df["packet_rate"]  = df["count"]       / df["duration"].clip(lower=0.001)
    df["packet_count"] = df["count"]

    feature_cols = [
        "packet_count", "total_bytes", "avg_size",
        "duration", "byte_rate", "packet_rate"
    ]

    # ── Training: use ONLY normal (benign) flows ──
    # Isolation Forest is unsupervised — trained on normal data only,
    # it learns to flag anomalous patterns as outliers.
    normal_df = df[df["label"] == "normal"][feature_cols].copy()
    normal_df = normal_df.clip(lower=0).fillna(0)

    # Cap extreme outliers at 99th percentile so scaler isn't skewed
    for col in feature_cols:
        cap = normal_df[col].quantile(0.99)
        normal_df[col] = normal_df[col].clip(upper=cap)

    X = normal_df.values
    print(f"✅ Feature matrix ready: {X.shape[0]:,} normal flows × {X.shape[1]} features")

else:
    # ── Synthetic fallback (realistic distributions) ──────
    print("🔄 Generating realistic synthetic training data as fallback...")

    normal_traffic = np.random.normal(
        loc=[20, 5000, 250, 5, 1000, 5],
        scale=[5, 2000, 50, 2, 500, 2],
        size=(1000, 6)
    ).clip(min=0)

    heavy_traffic = np.random.normal(
        loc=[200, 500_000, 1400, 20, 20_000, 20],
        scale=[50, 200_000, 300, 5, 10_000, 5],
        size=(200, 6)
    ).clip(min=0)

    X = np.vstack([normal_traffic, heavy_traffic])
    print(f"✅ Synthetic matrix ready: {X.shape[0]} samples × {X.shape[1]} features")

# ── Step 3: Scale ─────────────────────────────────────────
print("\n⚙️  Fitting StandardScaler...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ── Step 4: Train Isolation Forest ────────────────────────
print("🌲 Training Isolation Forest...")
print("   n_estimators : 300")
print("   contamination: 0.05  (5% anomaly rate)")
print("   max_features : 1.0")

model = IsolationForest(
    n_estimators=300,
    contamination=0.05,
    max_features=1.0,
    bootstrap=True,
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)

# ── Step 5: Save Artifacts ────────────────────────────────
joblib.dump(model,  "anomaly_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("\n✅ Model saved  → anomaly_model.pkl")
print("✅ Scaler saved → scaler.pkl")
print("\n🎉 Training complete! Re-run packet_capture.py to use the new model.")
print("=" * 55)