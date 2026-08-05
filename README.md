# Network Guardian 🛡

**Lightweight ML-based Network Anomaly Detector for Windows**

Real-time network traffic monitoring using ensemble Machine Learning (RandomForest + XGBoost + LightGBM) with automatic model updates, Telegram alerts, and actionable remediation steps.

---

## ✨ Features

- **🔍 Real-time Detection** — Captures network flows via `nfstream`, evaluates with ML ensemble (99.74% F1)
- **🤖 Ensemble Model** — RandomForest + XGBoost + LightGBM voting classifier
- **📱 Telegram Alerts** — Rich HTML notifications with flow details
- **🪟 Windows Toast** — Native desktop notifications
- **🛠 Remediation Advisor** — Specific next steps per threat type (DoS, Probe, R2L, U2R, Data Exfil, Malware C2, Phishing)
- **🔄 Auto-Upgrade** — Checks GitHub Releases every 6h, verifies SHA256, hot-swaps models
- **⚡ Lightweight** — Single `.exe` (~30-100 MB), runs as Windows Service (NSSM)
- **📊 Connection Tracking** — Computes `ct_*` features (connection counts per IP/port/service)

---

## 🚀 Quick Start

### 1. Download & Configure

```powershell
# Download latest release
# https://github.com/kstanisz88/anomaly-detector/releases/latest

# Edit config.yaml
notepad config.yaml
```

**Required config:**
```yaml
alerts:
  telegram_bot_token: "YOUR_BOT_TOKEN_FROM_BOTFATHER"
  telegram_chat_id: "YOUR_CHAT_ID_FROM_USERINFOBOT"
```

### 2. Install as Windows Service

```powershell
# Run as Administrator
network_guardian.exe --install-service
```

### 3. Manage Service

```powershell
# Start/Stop/Restart
net start NetworkGuardian
net stop NetworkGuardian

# Uninstall
network_guardian.exe --uninstall-service
```

---

## 🏗 Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  nfstream   │────▶│  Feature     │────▶│  Ensemble   │
│  Capture    │     │  Engineering │     │  (RF+XGB    │
└─────────────┘     └──────────────┘     │  +LGBM)     │
                                          └──────┬──────┘
                                                 │
                    ┌──────────────┐             ▼
                    │  Response    │     ┌─────────────┐
                    │  Advisor     │◀────│  Threat     │
                    └──────────────┘     │  Classifier │
                                         └─────────────┘
                                                 │
                    ┌──────────────┐             ▼
                    │   Alert      │     ┌─────────────┐
                    │  Manager     │◀────│  Auto       │
                    │ (Telegram/   │     │  Upgrader   │
                    │   Toast)     │     └─────────────┘
                    └──────────────┘
```

---

## 🎯 Threat Categories & Remediation

| Category | Examples | Key Actions |
|----------|----------|-------------|
| **DoS** | neptune, smurf, back, pod, teardrop | Block IP, rate limiting, contact ISP |
| **Probe** | nmap, ipsweep, portsweep, satan | Block IP, close unused ports, fail2ban |
| **R2L** | guess_passwd, ftp_write, imap, phf | Block IP, enforce MFA, check auth logs |
| **U2R** | buffer_overflow, rootkit, perl | **ISOLATE HOST**, memory dump, offline AV scan |
| **Data Exfil** | Large unusual outbound transfers | Block destination, identify process, DLP check |
| **Malware C2** | Beaconing, DGA domains | Sinkhole DNS, offline scan, IR procedure |
| **Phishing** | Suspicious URLs (phishing-detector model) | Don't click, report, block domain, rotate creds |

---

## ⚙️ Configuration (`config.yaml`)

```yaml
network:
  interface: "auto"           # Network interface (auto-detect)
  bpf_filter: ""              # BPF filter (e.g., "tcp port 80 or 443")
  idle_timeout: 120           # Flow idle timeout (seconds)
  enable_connection_tracking: true

model:
  threshold: 0.6              # Anomaly confidence threshold (0.0-1.0)
  model_dir: "models"

alerts:
  telegram_bot_token: ""      # FROM @BotFather
  telegram_chat_id: ""        # FROM @userinfobot
  enable_telegram: true
  enable_windows_toast: true
  cooldown_seconds: 60        # Min time between alerts
  min_confidence: 0.6

upgrade:
  manifest_url: "https://raw.githubusercontent.com/kstanisz88/anomaly-detector/main/model_manifest.json"
  check_interval_hours: 6
  enabled: true
```

---

## 🔄 Auto-Upgrade System

The app automatically checks for model updates:

1. **Manifest URL** — Points to `model_manifest.json` (hosted on GitHub Pages)
2. **Version Check** — Compares semantic versions
3. **Download & Verify** — Downloads `.pkl` files, verifies SHA256
4. **Hot-Swap** — Atomic file replacement, no restart needed
5. **Callback** — Notifies via Telegram when upgraded

**Manifest format:**
```json
{
  "version": "1.1.0",
  "model_url": "https://github.com/.../releases/download/v1.1.0/rf_anomaly_model.pkl",
  "scaler_url": "...",
  "encoders_url": "...",
  "sha256_model": "abc123...",
  "sha256_scaler": "def456...",
  "min_app_version": "1.0.0",
  "changelog": "Improved detection for encrypted traffic"
}
```

---

## 🛠 Development

### Setup

```bash
git clone https://github.com/kstanisz88/anomaly-detector.git
cd anomaly-detector

# Create venv
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install deps
pip install -r requirements.txt

# Train models (uses NSL-KDD dataset)
python src/train_model.py

# Run locally
python src/main.py --config config.yaml
```

### Build Windows Executable

```bash
# On Windows
python build.py build

# Or full pipeline (build + manifest)
python build.py all
```

### GitHub Actions CI/CD

Push a version tag to trigger automated build & release:

```bash
git tag v1.1.0
git push origin v1.1.0
```

Workflow: `.github/workflows/build-release.yml`
- Lints & tests on Ubuntu
- Builds `.exe` on Windows runner
- Creates GitHub Release with artifacts
- Deploys manifest to GitHub Pages
- Notifies via Telegram (if configured)

---

## 📊 Model Performance

| Metric | Value | Dataset |
|--------|-------|---------|
| Accuracy | 99.74% | NSL-KDD 20% |
| F1-Score | 99.72% | NSL-KDD 20% |
| Ensemble | RF + XGB + LGBM | Soft voting |

*Trained on NSL-KDD (proxy for UNSW-NB15 feature space)*

---

## 📦 Release Assets

Each release includes:
- `network_guardian.exe` — Standalone Windows executable
- `model_manifest.json` — Auto-upgrade manifest
- `*.pkl` — All model files
- `SHA256SUMS.txt` — Integrity checksums
- `config.yaml` — Example configuration

---

## 🔒 Security

- **No external dependencies at runtime** — Single embedded `.exe`
- **SHA256 verification** — All model downloads verified
- **No plaintext secrets** — Token only in local `config.yaml`
- **Least privilege** — Runs as standard user, service installed via NSSM

---

## 📝 License

MIT License — See [LICENSE](LICENSE)

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/kstanisz88/anomaly-detector/issues)
- **Telegram**: Configure bot for alerts
- **Documentation**: This README + inline code comments

---

**Built with ❤️ for network security**