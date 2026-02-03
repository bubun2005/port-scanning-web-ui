import streamlit as st
import socket
import time
import pandas as pd
import requests
from streamlit_lottie import st_lottie

from scanner import PortScanner, ScanType, OutputFormatter, parse_ports

# ---------------- Page Configuration ----------------
st.set_page_config(
    page_title="Port Scanning using NumPy",
    page_icon="🌐",
    layout="wide"
)

# ---------------- Load Lottie Animation ----------------
def load_lottie_url(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_scan = load_lottie_url(
    "https://assets2.lottiefiles.com/packages/lf20_jcikwtux.json"
)

# ---------------- Title ----------------
st.title("🌐 Port Scanning Tool")
st.markdown("### Web-based Port Scanner using Python & NumPy")

# ---------------- Ethical Warning ----------------
st.warning(
    "⚠️ Educational Use Only. Scan only systems you own or have permission to test."
)

# ---------------- Auto Detect Device IP ----------------
def get_device_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "Not detected"

device_ip = get_device_ip()
st.success(f"💻 Your Device IP Address: {device_ip}")

# ---------------- Input Section ----------------
st.header("🔧 Scan Configuration")

target = st.text_input(
    "Target IP / Hostname",
    value=device_ip
)

ports_input = st.text_input(
    "Ports (Example: 80,443 or 20-25 or common)",
    value="common"
)

scan_type_ui = st.selectbox(
    "Select Scan Type",
    ["TCP Connect Scan", "UDP Scan"]
)

# ---------------- Start Scan Button ----------------
if st.button("🚀 Start Scan"):
    if target.strip() == "":
        st.error("Target IP / Hostname is required")
    else:
        scanner = PortScanner()

        # Scan type mapping
        if scan_type_ui == "TCP Connect Scan":
            scan_mode = ScanType.TCP_CONNECT
        else:
            scan_mode = ScanType.UDP

        # Ports handling
        if ports_input.lower() == "common":
            ports = "common"
        else:
            ports = parse_ports(ports_input, False, False)

        # ---------------- Animation + Progress ----------------
        st.info("🔍 Scanning in progress...")
        st_lottie(lottie_scan, height=200)

        progress = st.progress(0)
        status = st.empty()

        for i in range(100):
            time.sleep(0.02)
            progress.progress(i + 1)
            status.text(f"Scanning... {i + 1}%")

        # ---------------- Perform Scan ----------------
        results = scanner.scan_multiple_hosts(
            [target],
            ports,
            scan_mode
        )

        status.text("Scan Completed ✅")
        st.success("Scan Completed Successfully")
        st.balloons()

        # ---------------- Fade-in Animation ----------------
        st.markdown("""
        <style>
        .fade-in {
            animation: fadeIn 1.5s;
        }
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        </style>
        """, unsafe_allow_html=True)

        st.markdown('<div class="fade-in">', unsafe_allow_html=True)

        # ---------------- Scan Summary ----------------
        open_ports = 0
        for host in results:
            for port in host.ports:
                if port.is_open:
                    open_ports += 1

        st.subheader("📊 Scan Summary")
        col1, col2 = st.columns(2)
        col1.metric("Target", target)
        col2.metric("Open Ports Found", open_ports)

        # ---------------- Result Table ----------------
        table_data = []

        for host in results:
            for port in host.ports:
                table_data.append({
                    "IP Address": host.ip,
                    "Port": port.port,
                    "Status": "OPEN 🟢" if port.is_open else "CLOSED 🔴",
                    "Service": port.service or "Unknown"
                })

        if table_data:
            df = pd.DataFrame(table_data)
            st.subheader("📋 Port Scan Results")
            st.dataframe(df, use_container_width=True)
        else:
            st.warning("No open ports found")

        # ---------------- Text Output ----------------
        st.subheader("📝 Detailed Scan Output")
        output_text = OutputFormatter.text(results, verbose=True)
        st.text_area("Output", output_text, height=300)

        st.markdown('</div>', unsafe_allow_html=True)

# ---------------- Footer ----------------
st.markdown(
    """
    <style>
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: #0e1117;
        color: white;
        text-align: center;
        padding: 8px;
        font-size: 14px;
    }
    </style>

    <div class="footer">
        Semester Project: Port Scanning using NumPy
    </div>
    """,
    unsafe_allow_html=True
)
