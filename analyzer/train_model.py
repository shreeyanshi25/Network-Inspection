import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

# ==============================
# Generate Realistic Normal Traffic
# ==============================

normal_traffic = np.random.normal(
    loc=[20, 5000, 250, 5, 1000, 5],  # typical browsing pattern
    scale=[5, 2000, 50, 2, 500, 2],
    size=(1000, 6)
)

# ==============================
# Generate Heavy Streaming Traffic
# ==============================

heavy_traffic = np.random.normal(
    loc=[200, 500000, 1400, 20, 20000, 20],
    scale=[50, 200000, 300, 5, 10000, 5],
    size=(200, 6)
)

# Combine
X = np.vstack([normal_traffic, heavy_traffic])

# ==============================
# Scale Data
# ==============================

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ==============================
# Train Isolation Forest
# ==============================

model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    random_state=42
)

model.fit(X_scaled)

# Save
joblib.dump(model, "anomaly_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("Model trained on realistic traffic and saved successfully.")