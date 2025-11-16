# PDC-Project: MPI-Based DDoS Detection System

[![License](https://img.shields.io/badge/license-Educational-blue.svg)](LICENSE)
[![MPI](https://img.shields.io/badge/MPI-MPICH%203.3%2B-green.svg)](https://www.mpich.org/)
[![Accuracy](https://img.shields.io/badge/accuracy-99.98%25-brightgreen.svg)](ddos_mpi_detector/README.md)

A high-performance, distributed Distributed Denial of Service (DDoS) detection system using Message Passing Interface (MPI) for parallel processing. Achieves 99.98% detection accuracy on the CIC-DDoS2019 dataset with real-time mitigation capabilities.

## 🌟 Features

- **Parallel Processing**: MPI-based master-worker architecture for distributed analysis
- **Triple Detection Algorithm**: Entropy + PCA + CUSUM with majority voting
- **Real-Time Mitigation**: Automated iptables blocking and tc rate limiting
- **Three Operating Modes**: Quick Start, Dataset Analysis, Live Capture
- **High Performance**: 10,000+ flows/second throughput
- **Low Latency**: <30 second detection in live mode
- **Comprehensive Tools**: Traffic capture, attack simulation, mitigation cleanup

## 📊 System Architecture

```
Network Traffic → Live Capture → MPI Detection → Mitigation
                     (10s)      (3 processes)   (iptables/tc)
                                      ↓
                            99.98% Accuracy
```

## 🚀 Quick Start

### Prerequisites

```bash
# Install MPI and dependencies
sudo apt-get update
sudo apt-get install -y mpich libmpich-dev build-essential
sudo apt-get install -y liblapacke-dev liblapack-dev libblas-dev
sudo apt-get install -y python3-scapy iproute2 iptables
```

### Installation

```bash
# Clone repository
git clone https://github.com/AbdulHadi57/PDC-Project.git
cd PDC-Project/ddos_mpi_detector

# Compile
make clean
make

# Run detection
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
```

## 📁 Project Structure

```
PDC-Project/
├── ddos_mpi_detector/          # Main detection system
│   ├── src/                    # Source code (C)
│   │   ├── core/              # Orchestrator, CSV parser
│   │   ├── detectors/         # Entropy, PCA, CUSUM
│   │   ├── mitigation/        # iptables/tc engine
│   │   └── utils/             # MPI helpers
│   ├── include/               # Header files
│   ├── bin/                   # Compiled binaries
│   ├── results/               # Detection output
│   ├── Makefile
│   ├── README.md              # Detailed documentation
│   ├── TESTING_GUIDE.md       # Testing instructions
│   ├── MPI_ARCHITECTURE.md    # MPI deep dive
│   └── cleanup_mitigation.sh  # Cleanup script
│
├── live_capture_tool/         # Traffic capture (Python)
│   ├── live_traffic_capture_continuous.py
│   └── README.md
│
├── attacker_vm/               # Attack simulation (Python)
│   ├── multi_attacker.py
│   └── README.md
│
├── prevention_pipeline/       # Prevention tools
│   ├── apply_prevention.py
│   ├── detectors/             # C implementations
│   └── bin/
│
├── Dataset/                   # CIC-DDoS2019 dataset (not in repo)
│   ├── CSV-01-12/
│   └── CSV-03-11/
│
└── README.md                  # This file
```

## 🔬 Components

### 1. MPI Detection System
- **Location**: `ddos_mpi_detector/`
- **Language**: C with MPI
- **Purpose**: Distributed DDoS detection and mitigation
- **Accuracy**: 99.98% on CIC-DDoS2019
- **Docs**: See [ddos_mpi_detector/README.md](ddos_mpi_detector/README.md)

### 2. Live Traffic Capture
- **Location**: `live_capture_tool/`
- **Language**: Python 3 with Scapy
- **Purpose**: Packet capture in 10-second windows
- **Output**: CSV files with 79 flow features
- **Docs**: See [live_capture_tool/README.md](live_capture_tool/README.md)

### 3. Attack Simulator
- **Location**: `attacker_vm/`
- **Language**: Python 3
- **Purpose**: Coordinated multi-attacker DDoS simulation
- **Attacks**: GoldenEye HTTP flood, Slowloris
- **Docs**: See [attacker_vm/README.md](attacker_vm/README.md)

### 4. Prevention Pipeline
- **Location**: `prevention_pipeline/`
- **Language**: Python + C
- **Purpose**: Real-time attack prevention

## 🎯 Usage Examples

### Example 1: Quick Dataset Analysis

```bash
cd ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
# Select: 1. Quick Start
```

**Output:**
```
Loaded 150 windows from dataset
  Total flows: 150,000

Analysis Complete!
  Accuracy: 99.98%
  Processing time: 12.3 seconds
```

### Example 2: Live Attack Detection with Mitigation

**Terminal 1 - Web Server:**
```bash
sudo python3 -m http.server 80
```

**Terminal 2 - Traffic Capture:**
```bash
cd live_capture_tool
sudo python3 live_traffic_capture_continuous.py -i eth0 \
    -o /mirror/ddos_mpi_detector/live_captures
```

**Terminal 3 - Detection:**
```bash
cd ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
# Select: 3. Live Network Capture
# Enable mitigation: y
```

**Terminal 4 - Attack:**
```bash
cd attacker_vm
python3 multi_attacker.py
# Launch coordinated attack
```

**Result:** Attack detected within 20-30 seconds, attacker IP blocked automatically.

### Example 3: Test Mitigation

```bash
# Check iptables rules
sudo iptables -L INPUT -n -v

# Check tc rate limiting
sudo tc filter show dev eth0 parent ffff:

# Cleanup after testing
cd ddos_mpi_detector
sudo ./cleanup_mitigation.sh
```

## 📈 Performance Benchmarks

| Metric | Value |
|--------|-------|
| **Accuracy** | 99.98% |
| **Throughput** | 10,000-15,000 flows/sec |
| **Detection Latency** | <30 seconds (live mode) |
| **False Positive Rate** | <0.02% |
| **Processing Time** | 82 ms/window (1000 flows) |
| **Scalability** | Near-linear up to 8 workers |

## 🛡️ Detection Algorithms

### 1. Entropy Detection
- Analyzes IP distribution entropy
- Detects anomalies in source/destination patterns
- Threshold: 0.20 (optimized for DrDoS)

### 2. PCA Detection
- Principal Component Analysis on 79 flow features
- Computes SPE (Squared Prediction Error) and T² statistics
- Threshold: 0.30

### 3. CUSUM Detection
- Cumulative Sum control charts
- Tracks changes in traffic patterns over time
- Threshold: 5.0

**Final Decision:** Majority voting across all detectors

## 🔧 Mitigation Features

### iptables Blocking
```bash
# Complete IP blocking
sudo iptables -I INPUT -s 192.168.10.20 -j DROP
```

### tc Rate Limiting
```bash
# Limit to 10 Mbps
sudo tc filter add dev eth0 parent ffff: protocol ip prio 1 \
    u32 match ip src 192.168.10.20 \
    police rate 10mbit burst 100k drop flowid :1
```

### Automated Application
- Triggered automatically when attacks detected
- Configurable thresholds and rate limits
- Minimum detection count (avoid false positives)
- Cleanup script for easy reset

## 📚 Documentation

- **[Main README](ddos_mpi_detector/README.md)** - System overview and installation
- **[Testing Guide](ddos_mpi_detector/TESTING_GUIDE.md)** - Step-by-step testing for all modes
- **[MPI Architecture](ddos_mpi_detector/MPI_ARCHITECTURE.md)** - Deep dive into parallel processing
- **[Capture Tool](live_capture_tool/README.md)** - Traffic capture documentation
- **[Attack Simulator](attacker_vm/README.md)** - Multi-attacker guide

## 🧪 Testing

See [TESTING_GUIDE.md](ddos_mpi_detector/TESTING_GUIDE.md) for comprehensive testing instructions including:
- Mode 1: Quick Start (default dataset)
- Mode 2: Dataset Analysis (custom configuration)
- Mode 3: Live Capture (real-time detection)
- Mitigation verification (iptables and tc)
- Performance testing

## 🔐 Security & Ethics

⚠️ **WARNING**: This system is for **educational and authorized testing only**.

- Only use on isolated test networks you own
- Never attack production systems without authorization
- Unauthorized DDoS attacks are illegal in most jurisdictions
- Keep test traffic on dedicated lab networks

## 🐛 Troubleshooting

### MPI Deadlock
```bash
# Check if workers are active
ps aux | grep ddos_orchestrator

# Kill hung processes
pkill -9 ddos_orchestrator
```

### No Mitigation Applied
```bash
# Check root privileges
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator

# Verify network interface
ip link show
```

### Victim IP Blocked
- Fixed in latest version with server IP exclusion
- Update `live_traffic_capture_continuous.py` to latest version

## 🚧 Known Issues & Fixes

✅ **Fixed Issues:**
- MPI workers deadlock in live mode (v1.1) - Workers now persist between windows
- Victim IP being blocked (v1.1) - Server IP exclusion implemented
- tc rate limiting not working (v1.1) - Proper ingress qdisc creation

## 📊 Dataset

This system is tested on **CIC-DDoS2019** dataset:
- 50 million flows
- 12 DDoS attack types (DrDoS DNS, NTP, LDAP, MSSQL, NetBIOS, SNMP, SSDP, UDP, Syn, TFTP, UDPLag, Portmap)
- Realistic benign traffic
- Available at: [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ddos-2019.html)

**Note:** Dataset files are not included in this repository due to size (50+ GB). Download separately.

## 🤝 Contributing

This is an educational project. Contributions, suggestions, and improvements are welcome!

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is for **educational purposes only**. Use responsibly and ethically.

## 👥 Authors

- **Abdul Hadi** - Initial work and implementation

## 🙏 Acknowledgments

- CIC-DDoS2019 dataset creators
- MPICH development team
- Scapy packet manipulation library
- Open-source security research community

## 📞 Contact

For questions, issues, or collaboration:
- GitHub: [@AbdulHadi57](https://github.com/AbdulHadi57)
- Repository: [PDC-Project](https://github.com/AbdulHadi57/PDC-Project)

## 🔖 Version History

- **v1.1** (Current)
  - Fixed live mode MPI deadlock
  - Implemented server IP exclusion
  - Fixed tc rate limiting
  - Added comprehensive documentation

- **v1.0** (Initial)
  - Core MPI detection system
  - Triple algorithm detection
  - Basic mitigation support

---

**⚠️ Disclaimer**: This tool generates real network attacks and applies real mitigation rules. Use only in authorized, isolated test environments. The authors are not responsible for misuse or damage caused by this software.
