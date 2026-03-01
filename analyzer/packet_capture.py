import requests
import joblib
import numpy as np
import time
import ipaddress

from scapy.all import sniff, IP, TCP, DNSQR, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.handshake import TLSClientHello

from blacklist import MALICIOUS_DOMAINS, SUSPICIOUS_KEYWORDS

# ==============================
# Load ML model + scaler
# ==============================
model = joblib.load("anomaly_model.pkl")
scaler = joblib.load("scaler.pkl")

flows = {}
BACKEND_URL = "http://localhost:5000/api/flows"
CAPTURE_INTERVAL = 10

# ==============================
# Geo-IP Cache (avoid hammering API)
# ==============================
geo_cache = {}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

def is_private_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in PRIVATE_RANGES)
    except ValueError:
        return True

def get_geo(ip_str):
    """Return (country_name, country_code) for an IP. Cached."""
    if ip_str in geo_cache:
        return geo_cache[ip_str]

    if is_private_ip(ip_str):
        result = ("Local Network", "🏠")
        geo_cache[ip_str] = result
        return result

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip_str}?fields=status,country,countryCode",
            timeout=3
        )
        data = r.json()
        if data.get("status") == "success":
            country = data.get("country", "Unknown")
            code    = data.get("countryCode", "?")
            # Convert country code to flag emoji
            flag = "".join(
                chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper()
            ) if len(code) == 2 else "🌐"
            result = (country, flag)
        else:
            result = ("Unknown", "🌐")
    except Exception:
        result = ("Unknown", "🌐")

    geo_cache[ip_str] = result
    return result


# ==============================
# Extract Layer 7 Data (DPI)
# ==============================
def extract_application_data(packet):
    dns_query = None
    http_host = None
    tls_sni   = None

    if packet.haslayer(DNSQR):
        dns_query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")

    if packet.haslayer(HTTPRequest):
        try:
            http_host = packet[HTTPRequest].Host.decode(errors="ignore")
        except Exception:
            pass

    if packet.haslayer(TLSClientHello):
        try:
            for ext in packet[TLSClientHello].ext:
                if hasattr(ext, "servernames"):
                    tls_sni = ext.servernames[0].servername.decode()
        except Exception:
            pass

    return dns_query, http_host, tls_sni


# ==============================
# Process Packet
# ==============================
def process_packet(packet):
    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    key = (src, dst)

    now  = time.time()
    size = len(packet)

    if key not in flows:
        flows[key] = {
            "packet_count": 0,
            "total_bytes":  0,
            "start_time":   now,
            "last_time":    now,
            "dns_query":    None,
            "http_host":    None,
            "tls_sni":      None,
        }

    flow = flows[key]
    flow["packet_count"] += 1
    flow["total_bytes"]  += size
    flow["last_time"]     = now

    dns_query, http_host, tls_sni = extract_application_data(packet)
    if dns_query: flow["dns_query"] = dns_query
    if http_host: flow["http_host"] = http_host
    if tls_sni:   flow["tls_sni"]   = tls_sni


# ==============================
# Analyze + Send to Backend
# ==============================
def send_flows_to_backend():
    print("\nAnalyzing & Sending flows...\n")

    for (src, dst), data in flows.items():

        if data["packet_count"] == 0:
            continue

        duration   = data["last_time"] - data["start_time"]
        avg_size   = data["total_bytes"] / data["packet_count"]
        byte_rate  = data["total_bytes"] / duration if duration > 0 else 0
        packet_rate= data["packet_count"] / duration if duration > 0 else 0

        # ── ML Feature Vector ──────────────────────────────
        features = np.array([[
            data["packet_count"],
            data["total_bytes"],
            avg_size,
            duration,
            byte_rate,
            packet_rate
        ]])

        scaled_features  = scaler.transform(features)
        prediction_raw   = model.predict(scaled_features)[0]
        score            = model.decision_function(scaled_features)[0]

        anomaly_score    = -score
        base_threat_score= min(max(anomaly_score * 100, 0), 100)
        prediction       = "Normal" if prediction_raw == 1 else "Suspicious"

        # ── DPI Domain Intelligence ────────────────────────
        domain = data["dns_query"] or data["http_host"] or data["tls_sni"]
        domain_risk_score = 0

        if domain:
            domain_lower = domain.lower()
            if domain_lower in MALICIOUS_DOMAINS:
                domain_risk_score += 50
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in domain_lower:
                    domain_risk_score += 10

        threat_score = round(min(base_threat_score + domain_risk_score, 100), 2)

        # ── Threat Level ───────────────────────────────────
        if   threat_score > 80: threat_level = "Critical"
        elif threat_score > 60: threat_level = "High"
        elif threat_score > 40: threat_level = "Medium"
        else:                   threat_level = "Low"

        # ── Geo-IP Lookup ──────────────────────────────────
        src_country, src_flag = get_geo(src)
        dst_country, dst_flag = get_geo(dst)

        flow_data = {
            "src_ip":           src,
            "dst_ip":           dst,
            "packet_count":     data["packet_count"],
            "total_bytes":      data["total_bytes"],
            "avg_packet_size":  round(avg_size, 2),
            "duration":         round(duration, 2),
            "byte_rate":        round(byte_rate, 2),
            "packet_rate":      round(packet_rate, 2),
            "prediction":       prediction,
            "threat_level":     threat_level,
            "threat_score":     threat_score,
            "dns_query":        data["dns_query"],
            "http_host":        data["http_host"],
            "tls_sni":          data["tls_sni"],
            # Geo-IP
            "src_country":      src_country,
            "src_country_code": src_flag,
            "dst_country":      dst_country,
            "dst_country_code": dst_flag,
        }

        print(f"  {src} ({src_flag}) → {dst} ({dst_flag})  [{threat_level}]  score={threat_score}%")

        try:
            response = requests.post(BACKEND_URL, json=flow_data)
            print(f"  Sent to backend: {response.status_code}")
        except Exception as e:
            print(f"  Error sending to backend: {e}")

    flows.clear()


# ==============================
# Continuous Monitoring
# ==============================
def start_monitoring():
    print("🚀 AI + DPI Real-Time Monitoring Started (NSL-KDD Model)\n")
    print("Press CTRL + C to stop.\n")

    try:
        while True:
            sniff(prn=process_packet, store=False, timeout=CAPTURE_INTERVAL)
            send_flows_to_backend()
    except KeyboardInterrupt:
        print("\n🛑 Monitoring Stopped Safely.")


if __name__ == "__main__":
    start_monitoring()