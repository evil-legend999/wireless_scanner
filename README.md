# Cross-Platform Wireless Network Scanner & Auditor

A modular, lightweight Python tool designed to scan ambient Wi-Fi access points across Linux, Windows, and macOS networks. The application profiles local frequencies, extracts vital signal telemetry, audits active encryption security strengths, and exports clean reporting deliverables to the local Desktop environment.

---

## 📂 System Architecture

The application implements a clean multi-module workflow where data ingest, security audit layers, and presentation assets are strictly isolated:

* **`main.py`:** Core controller plane. Orchestrates module loops, builds the native console interface, and maps data export flows.
* **`discovery.py`:** Hardware communication engine. Uses system identification branches (`sys.platform`) to execute appropriate low-level system commands (`nmcli`, `netsh`, or `airport`).
* **`security_flags.py`:** Cryptographic analysis component. Categorizes and flags protocol vulnerability layers (`HIGH`, `MEDIUM`, `LOW`).
* **`visualisation.py`:** Graphical generation asset. Leverages Matplotlib to plot, sort, and color-code regional signal coverage performance structures.

---

## 🛠️ Features & Functionality

1. **Multi-OS Execution:** Drop-in compatibility without changing code layers for Debian-based Linux, Microsoft Windows (PowerShell/Terminal), and macOS environments.
2. **Real-Time Signal Dashboards:** Generates clean Unicode block layouts (`████░░░░`) directly inside terminal sessions.
3. **Automated Security Assessments:** Dynamically evaluates vulnerabilities based on encryption strings.
4. **Desktop Export Automation:** Automatically generates an external folder named `Wireless_Scan_Reports/` directly on the local system Desktop to drop time-stamped files:
   * **`.txt` Report:** Complete diagnostic trace log detailing SSIDs, BSSIDs, active channels, and security classifications.
   * **`.png` Graph:** Matplotlib horizontal bar chart representing relative network coverage strengths.

---

## 🚀 Installation & Deployment

### Dependencies
Ensure your Python environment contains the necessary data visualization libraries:
```bash
pip install matplotlib
