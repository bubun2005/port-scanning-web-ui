import streamlit as st
import socket
import time
import pandas as pd
import requests
from streamlit_lottie import st_lottie

from scanner import PortScanner, ScanType, OutputFormatter, parse_ports

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Port Scanning using NumPy",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- FORCE HACKER THEME ----------------
st.markdown("""
<style>
/* Main background */
.stApp {
    background-color: #020617;
    color: #00ff9c;
}

/* Titles */
h1, h2, h3, h4 {
    color: #00ff9c !important;
    text-shadow: 0 0 10px #00ff9c;
}

/* Input boxes */
input, textarea {
    background-color: #020617 !important;
    color: #00ff9c !important;
    border: 1px solid #00ff9c !important;
}

/* Buttons */
button {
    background-color: #000000 !important;
    color: #00ff9c !important;
    border: 1px solid #00ff9c !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    background-color: #020617;
}
</style>
""", unsafe_allow_html=True)

# ---------------- LOAD LOTTIE ----------------
def load_lottie_url(url):
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

lottie_scan = load_lottie_url(
    "https://assets2.lottiefiles.com/packages/lf20_jcikwtux.json"
)

# ---------------- IP DETECTION ----------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "Not detected"

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org").text
    except:
        return "Not detected"

local_ip = get_local_ip()
public_ip = get_public_ip()

# ---------------- TITLE ----------------
st.title("🛡️ PORT SCANNING TOOL")
st.markdown("#⚡using| Python + NumPy ⚡|")

# ---------------- WARNING ----------------
st.warning("⚠️ FOR EDUCATIONAL USE")

# ---------------- SHOW IPs ----------------
col1, col2 = st.columns(2)
col1.success(f"💻 Local IP Address: **{local_ip}**")
col2.success(f"🌍 Public IP Address: **{public_ip}**")

# ---------------- INPUT SECTION ----------------
st.header("🔧 Scan Configuration")

target = st.text_input("Target IP / Hostname", value=local_ip)

ports_input = st.text_input(
    "Ports (80,443 | 20-25 | common)",
    value="common"
)

scan_type_ui = st.selectbox(
    "Scan Type",
    ["TCP Connect Scan", "UDP Scan"]
)

# ---------------- SCAN BUTTON ----------------
if st.button("🚀 START SCAN"):
    if not target.strip():
        st.error("Target IP is required")
    else:
        scanner = PortScanner()
        scan_mode = ScanType.TCP_CONNECT if scan_type_ui == "TCP Connect Scan" else ScanType.UDP

        ports = "common" if ports_input.lower() == "common" else parse_ports(ports_input, False, False)

        st.info("🔍 Scanning target...")
        if lottie_scan:
            st_lottie(lottie_scan, height=200)

        progress = st.progress(0)
        for i in range(100):
            time.sleep(0.02)
            progress.progress(i + 1)

        results = scanner.scan_multiple_hosts([target], ports, scan_mode)

        st.success("✅ Scan Completed")
        st.balloons()

        # ---------------- SUMMARY ----------------
        open_ports = sum(port.is_open for host in results for port in host.ports)

        st.subheader("📊 Scan Summary")
        c1, c2 = st.columns(2)
        c1.metric("Target", target)
        c2.metric("Open Ports", open_ports)

        # ---------------- TABLE ----------------
        table = []
        for host in results:
            for port in host.ports:
                table.append({
                    "IP": host.ip,
                    "Port": port.port,
                    "Status": "OPEN 🟢" if port.is_open else "CLOSED 🔴",
                    "Service": port.service or "Unknown"
                })

        if table:
            df = pd.DataFrame(table)
            st.subheader("📋 Port Scan Results")
            st.dataframe(df, use_container_width=True)

        # ---------------- TEXT OUTPUT ----------------
        st.subheader("🧾 Detailed Output")
        st.text_area(
            "Scan Log",
            OutputFormatter.text(results, verbose=True),
            height=300
        )

# ---------------- FOOTER ----------------
st.markdown("""
<hr style="border:1px solid #00ff9c">
<center>
🛡️ Semester Project | Port Scanning using NumPy | Ethical Hacking
</center>
""", unsafe_allow_html=True)

import socket
import requests
import streamlit as st

# ---------------- ACCURATE LOCAL IP ----------------
@st.cache_data(show_spinner=False)
def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ips = socket.gethostbyname_ex(hostname)[2]

        # Filter valid IPv4 addresses
        for ip in local_ips:
            if ip.startswith(("192.", "10.", "172.")):
                return ip
        return local_ips[0] if local_ips else "Not detected"

    except Exception as e:
        return "Not detected"

# ---------------- ACCURATE PUBLIC IP ----------------
@st.cache_data(show_spinner=False)
def get_public_ip():
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com"
    ]

    for service in services:
        try:
            ip = requests.get(service, timeout=3).text.strip()
            if ip:
                return ip
        except:
            continue

    return "Not detected"

local_ip = get_local_ip()
public_ip = get_public_ip()

st.info("🌐 Network Status: Online" if public_ip != "Not detected" else "🌐 Network Status: Offline")
