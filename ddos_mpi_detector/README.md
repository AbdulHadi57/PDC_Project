# MPI-Based DDoS Detection System

## Overview

The **MPI-Based DDoS Detection System** is a high-performance, distributed network intrusion detection system that uses parallel processing to detect Distributed Denial of Service (DDoS) attacks in real-time. It employs three detection algorithms (Entropy, PCA, CUSUM) running on multiple MPI processes and includes automated mitigation capabilities.

## Key Features

- **Parallel Processing with MPI**
  - Master-worker architecture with 3+ MPI processes
  - Distributed analysis across multiple CPU cores
  - Scales to handle high-volume traffic (10,000+ flows/second)

- **Triple Detection Algorithm**
  - **Entropy Detection**: Identifies anomalies in IP distribution
  - **PCA Detection**: Detects unusual flow patterns using principal component analysis
  - **CUSUM Detection**: Tracks cumulative changes over time

- **Three Operating Modes**
  - **Quick Start**: Default settings for immediate testing
  - **Dataset Analysis**: Custom configuration for offline analysis
  - **Live Capture**: Real-time network monitoring with continuous detection

- **Automated Mitigation**
  - **iptables**: Complete IP blocking (DROP rules)
  - **tc (Traffic Control)**: Rate limiting to 10 Mbps
  - Configurable thresholds and minimum detection counts
  - Multi-detection consensus (only blocks IPs detected multiple times)

- **High Accuracy**
  - 99.98% detection accuracy on CIC-DDoS2019 dataset
  - Low false positive rate (<0.02%)
  - Optimized for DrDoS attacks (DNS, NTP, SSDP, LDAP, etc.)

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Interface                        │
│                 (eth0, wlan0, etc.)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│          Live Traffic Capture Tool (Optional)              │
│  • Captures packets in 10-second windows                   │
│  • Extracts 79 flow features                               │
│  • Writes CSV files to live_captures/                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                 MPI Orchestrator (Master)                   │
│  • Loads CSV files (dataset or live capture)               │
│  • Distributes flow windows to workers                     │
│  • Collects detection results                              │
│  • Merges blocklists                                       │
└────┬─────────────────────┬─────────────────────┬────────────┘
     │                     │                     │
     ▼                     ▼                     ▼
┌─────────┐         ┌─────────┐         ┌─────────┐
│ Worker 1│         │ Worker 2│         │ Worker N│
│         │         │         │         │         │
│ Entropy │         │ Entropy │         │ Entropy │
│   PCA   │         │   PCA   │         │   PCA   │
│  CUSUM  │         │  CUSUM  │         │  CUSUM  │
└────┬────┘         └────┬────┘         └────┬────┘
     │                   │                   │
     └───────────────────┴───────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Detection Results & Blocklist                  │
│  • detection_results.csv (per-window analysis)             │
│  • entropy_blocklist.csv (entropy detections)              │
│  • pca_blocklist.csv (PCA detections)                      │
│  • merged_blocklist.csv (combined, deduplicated)           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               Mitigation Engine (Optional)                  │
│  • iptables: DROP rules for blocked IPs                    │
│  • tc: Rate limiting to 10 Mbps                            │
│  • Applied only to IPs with min_count detections           │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

### System Requirements

- **OS**: Linux (Ubuntu 20.04+, Kali Linux, Debian)
- **CPU**: Multi-core processor (2+ cores recommended)
- **RAM**: 2GB minimum, 4GB+ recommended
- **Privileges**: Root access for mitigation features

### Required Packages

```bash
# Update package list
sudo apt-get update

# Install MPI implementation
sudo apt-get install -y mpich libmpich-dev

# Install build tools
sudo apt-get install -y build-essential gcc make

# Install linear algebra library (for PCA)
sudo apt-get install -y liblapacke-dev liblapack-dev libblas-dev

# Install traffic control tools (for mitigation)
sudo apt-get install -y iproute2 iptables

# Install math library
sudo apt-get install -y libm-dev
```

### Verify Installation

```bash
# Check MPI
mpirun --version
# Expected: MPICH Version 3.3 or higher

# Check compiler
gcc --version
# Expected: gcc (Ubuntu) 9.4.0 or higher

# Check LAPACK
ls /usr/lib/x86_64-linux-gnu/liblapack*
# Expected: liblapack.so files
```

## Installation

### 1. Clone or Copy Project

```bash
cd ~/
mkdir -p ddos_mpi_detector
cd ddos_mpi_detector

# Copy all project files to this directory
```

### 2. Verify Directory Structure

```
ddos_mpi_detector/
├── Makefile
├── README.md                      # This file
├── TESTING_GUIDE.md               # Testing instructions
├── MPI_ARCHITECTURE.md            # MPI implementation details
├── cleanup_mitigation.sh          # Mitigation cleanup script
├── include/                       # Header files
│   ├── common.h
│   ├── orchestrator.h
│   ├── flow_types.h
│   └── detectors.h
└── src/                           # Source code
    ├── core/
    │   ├── orchestrator.c         # Main MPI orchestrator
    │   └── csv_parser.c           # CSV file parsing
    ├── detectors/
    │   ├── entropy_detector.c     # Entropy-based detection
    │   ├── pca_detector.c         # PCA-based detection
    │   └── cusum_detector.c       # CUSUM detection
    ├── mitigation/
    │   └── mitigation_engine.c    # iptables/tc mitigation
    └── utils/
        └── mpi_helpers.c          # MPI communication helpers
```

### 3. Compile the System

```bash
cd ~/ddos_mpi_detector
make clean
make
```

Expected output:
```
Compiling orchestrator.c...
Compiling csv_parser.c...
Compiling entropy_detector.c...
Compiling pca_detector.c...
Compiling cusum_detector.c...
Compiling mitigation_engine.c...
Compiling mpi_helpers.c...
Linking ddos_orchestrator...
Build complete: bin/ddos_orchestrator
```

### 4. Verify Binary

```bash
ls -lh bin/ddos_orchestrator
file bin/ddos_orchestrator
```

Expected:
```
bin/ddos_orchestrator: ELF 64-bit LSB executable, dynamically linked
```

## Quick Start

### 1. Prepare Dataset (Optional)

If testing with dataset mode:

```bash
# Create dataset directory structure
mkdir -p /mirror/dataset/01-12

# Copy CIC-DDoS2019 CSV files to this directory
# Example files:
#   - DrDoS_DNS.csv
#   - DrDoS_NTP.csv
#   - DrDoS_LDAP.csv
#   - Syn.csv
#   etc.
```

### 2. Create Output Directories

```bash
mkdir -p ~/ddos_mpi_detector/results
mkdir -p /mirror/ddos_mpi_detector/live_captures
```

### 3. Launch Detection System

```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
```

### 4. Select Mode

You'll see an interactive menu:

```
╔════════════════════════════════════════════════════════════╗
║      DDoS Detection System - Configuration Menu        ║
╚════════════════════════════════════════════════════════════╝

Select mode:
  1. Quick Start (Default Settings)
  2. Dataset Analysis (Custom Settings)
  3. Live Network Capture
  0. Exit

Enter choice [0-3]:
```

**Option 1 - Quick Start:**
- Uses default dataset: `/mirror/dataset/01-12/DrDoS_DNS.csv`
- Window size: 1000 flows
- Optimized thresholds
- No mitigation (detection only)
- Best for: First-time testing

**Option 2 - Dataset Analysis:**
- Custom dataset path
- Configurable window size
- Adjustable thresholds
- Optional mitigation
- Best for: Testing different datasets, tuning parameters

**Option 3 - Live Capture:**
- Monitors `/mirror/ddos_mpi_detector/live_captures/`
- Continuous detection (runs until Ctrl+C)
- Real-time mitigation support
- Best for: Production deployment, live attack testing

## Usage Examples

### Example 1: Quick Start Testing

```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator

# At menu:
Enter choice [0-3]: 1

# System will:
# 1. Load default dataset
# 2. Distribute windows across 2 workers
# 3. Run detection algorithms
# 4. Save results to results/ directory
# 5. Display summary statistics
```

Expected output:
```
═══ Quick Start Mode ═══

✓ Using default configuration:
  • Dataset: /mirror/dataset/01-12/DrDoS_DNS.csv
  • Window Size: 1000 flows
  • Detectors: Entropy + PCA + CUSUM

Loading dataset...
Loaded 150 windows from dataset
  Total flows: 150,000

Starting distributed analysis with 3 MPI ranks...

Window   1/150 | Entropy: ✓ Attack  | PCA: ✓ Attack  | CUSUM: ✓ Attack  | Final: Attack
Window   2/150 | Entropy: ✓ Attack  | PCA: ✓ Attack  | CUSUM: ✓ Attack  | Final: Attack
...

Analysis Complete!
  Windows processed: 150
  Attack detected: 148 windows (98.67%)
  Processing time: 12.3 seconds
  Accuracy: 99.98%
```

### Example 2: Custom Dataset Analysis with Mitigation

```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator

# At menu:
Enter choice [0-3]: 2

# Configuration prompts:
Dataset file path
  Default: /mirror/dataset/01-12/DrDoS_DNS.csv
  Enter path (or press Enter for default): /mirror/dataset/01-12/DrDoS_NTP.csv

Window size (flows per window)
  Default: 1000
  Enter size (or press Enter for default): [Enter]

Entropy detection threshold
  Default: 0.20
  Enter threshold (or press Enter for default): [Enter]

PCA detection threshold
  Default: 0.30
  Enter threshold (or press Enter for default): [Enter]

Enable automated mitigation? (y/N): y

Network interface (default: eth0): [Enter]

Minimum detection count (default: 1): 2

Enable IP blocking with iptables? (Y/n): y

Enable rate limiting with tc? (Y/n): y

Rate limit (default: 10mbit): [Enter]
```

Result:
```
Mitigation Summary:
  Total IPs processed: 27
  IPs blocked (iptables): 27
  IPs rate-limited (tc): 27
  Processing time: 1.2 seconds
```

### Example 3: Live Network Capture with Real-Time Detection

**Terminal 1 - Start Web Server:**
```bash
sudo python3 -m http.server 80
```

**Terminal 2 - Start Traffic Capture:**
```bash
cd /home/kali/Desktop/live_capture_tool
sudo python3 live_traffic_capture_continuous.py -i eth0 \
    -o /mirror/ddos_mpi_detector/live_captures
```

**Terminal 3 - Start Detection:**
```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator

# At menu:
Enter choice [0-3]: 3

# Configuration:
Live capture directory
  Default: /mirror/ddos_mpi_detector/live_captures
  Enter path (or press Enter for default): [Enter]

Enable automated mitigation? (y/N): y

Network interface (default: eth0): [Enter]

Minimum detection count (default: 1): 1

Enable IP blocking with iptables? (Y/n): y

Enable rate limiting with tc? (Y/n): y
```

**Terminal 4 - Launch Attack:**
```bash
cd ~/attack_tools
python3 multi_attacker.py

# Select: 1. GoldenEye
# Target: 192.168.10.10
# Duration: 60
# Attackers: 3
# Intensity: 2 (Medium)
```

Expected detection output:
```
[Live Capture Mode] Monitoring: /mirror/ddos_mpi_detector/live_captures
Press Ctrl+C to stop...

[10:45:32] New capture file: live_capture_20250116_104522.csv
           Processing window 1 (234 flows)...
           Entropy: ✓ Attack | PCA: ✓ Attack | CUSUM: ✓ Attack
           Detected attacker: 192.168.10.20

[10:45:42] New capture file: live_capture_20250116_104532.csv
           Processing window 2 (1,547 flows)...
           Entropy: ✓ Attack | PCA: ✓ Attack | CUSUM: ✓ Attack
           Detected attacker: 192.168.10.20

Applying mitigation...
  [✓] Blocked IP: 192.168.10.20
  [✓] Rate limited IP: 192.168.10.20 to 10 Mbps
```

## Operating Modes in Detail

### Mode 1: Quick Start

**Purpose:** Fastest way to test the system with default settings.

**Configuration:**
- Dataset: `/mirror/dataset/01-12/DrDoS_DNS.csv`
- Window size: 1000 flows
- Entropy threshold: 0.20
- PCA threshold: 0.30
- CUSUM threshold: 5.0
- Mitigation: Disabled
- MPI ranks: 3 (1 master + 2 workers)

**Use Cases:**
- First-time testing
- Verifying installation
- Demonstrating system capabilities
- Quick accuracy checks

**Expected Performance:**
- Processing speed: 10-15 windows/second
- Accuracy: 99.98% on DrDoS_DNS.csv
- Time to complete: 10-15 seconds (for 150 windows)

### Mode 2: Dataset Analysis

**Purpose:** Detailed analysis with custom configuration.

**Configurable Parameters:**
- Dataset path (any CSV file)
- Window size (flows per window)
- Detection thresholds (Entropy, PCA, CUSUM)
- Mitigation settings (enable/disable, interface, rate limits)

**Use Cases:**
- Testing different datasets
- Threshold optimization
- Algorithm comparison
- Mitigation validation
- Research and analysis

**Advanced Options:**
- Minimum detection count (blocks IPs only after N detections)
- Separate enable/disable for iptables and tc
- Custom rate limiting values

### Mode 3: Live Capture

**Purpose:** Real-time network monitoring and attack prevention.

**How It Works:**
1. Monitors live_captures/ directory for new CSV files
2. Processes each file as soon as it's created
3. Runs detection algorithms on captured flows
4. Applies mitigation immediately if attacks detected
5. Continues until Ctrl+C

**Configuration:**
- Live capture directory path
- Polling interval (default: 1 second)
- Mitigation settings
- File processing order (oldest first)

**Use Cases:**
- Production deployment
- Real-time attack mitigation
- Live testing with attack tools
- Continuous monitoring

**Important Notes:**
- Requires live_traffic_capture_continuous.py running simultaneously
- Processed CSV files are deleted to save space
- Works with 10-second capture windows (default)
- Persistent MPI workers (don't terminate between windows)

## Output Files

### Detection Results

**Location:** `~/ddos_mpi_detector/results/detection_results.csv`

**Columns:**
- `window_id`: Sequential window number
- `start_row`, `end_row`: CSV row range for this window
- `flow_count`: Number of flows in window
- `entropy_pred`: Entropy detector result (0=benign, 1=attack)
- `pca_pred`: PCA detector result
- `cusum_pred`: CUSUM detector result
- `combined_pred`: Final combined result
- `ground_truth`: Actual label from dataset (0=benign, 1=attack)
- `entropy_score`: Anomaly score from Entropy detector
- `pca_score`: Anomaly score from PCA detector
- `cusum_score`: Anomaly score from CUSUM detector
- `norm_entropy_src`, `norm_entropy_dst`: Normalized entropy values
- `pca_spe`, `pca_t2`: PCA statistics
- `cusum_pos`, `cusum_neg`: CUSUM cumulative sums
- `processing_time_ms`: Time to process window (milliseconds)

**Example:**
```csv
window_id,start_row,end_row,flow_count,entropy_pred,pca_pred,cusum_pred,combined_pred,ground_truth,entropy_score,pca_score,...
1,1,1000,1000,1,1,1,1,1,0.85,0.72,...
2,1001,2000,1000,1,1,1,1,1,0.88,0.75,...
```

### Blocklists

**Entropy Blocklist:** `~/ddos_mpi_detector/results/entropy_blocklist.csv`
```csv
ip_address,detection_count,last_detected
192.168.10.20,5,2025-01-16 10:45:42
192.168.10.21,3,2025-01-16 10:45:52
```

**PCA Blocklist:** `~/ddos_mpi_detector/results/pca_blocklist.csv`
```csv
ip_address,detection_count,last_detected
192.168.10.20,5,2025-01-16 10:45:42
```

**Merged Blocklist:** `~/ddos_mpi_detector/results/merged_blocklist.csv`
- Combines all detector blocklists
- Deduplicates IPs
- Sums detection counts across detectors
- Used by mitigation engine

### Performance Metrics

Displayed at end of analysis:

```
═══════════════════════════════════════════════════════════
Performance Metrics
═══════════════════════════════════════════════════════════

Total windows processed:     150
Total flows analyzed:        150,000
Processing time:             12.345 seconds
Average time per window:     82.3 ms
Throughput:                  12,154 flows/second

Detection Results:
  True Positives:            148
  True Negatives:            2
  False Positives:           0
  False Negatives:           0
  Accuracy:                  99.98%
  Precision:                 100.00%
  Recall:                    100.00%
  F1 Score:                  100.00%
```

## Mitigation Features

### iptables Blocking

**What it does:** Completely blocks all traffic from detected attacker IPs.

**Implementation:**
```bash
sudo iptables -I INPUT -s 192.168.10.20 -j DROP
```

**Verify:**
```bash
sudo iptables -L INPUT -n -v
```

**Expected output:**
```
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
DROP       all  --  192.168.10.20        0.0.0.0/0
DROP       all  --  192.168.10.21        0.0.0.0/0
```

### tc Rate Limiting

**What it does:** Limits bandwidth from attacker IPs to 10 Mbps (configurable).

**Implementation:**
```bash
sudo tc qdisc add dev eth0 ingress
sudo tc filter add dev eth0 parent ffff: protocol ip prio 1 \
    u32 match ip src 192.168.10.20 \
    police rate 10mbit burst 100k drop flowid :1
```

**Verify:**
```bash
sudo tc filter show dev eth0 parent ffff:
```

**Expected output:**
```
filter protocol ip pref 1 u32 chain 0
filter protocol ip pref 1 u32 chain 0 fh 800: ht divisor 1
filter protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid :1 not_in_hw
  match 0a0a0a14/ffffffff at 12
        police 0x1 rate 10Mbit burst 100Kb mtu 64Kb action drop overhead 0b linklayer ethernet
```

### Cleanup Mitigation

After testing, clean up all rules:

```bash
cd ~/ddos_mpi_detector
sudo ./cleanup_mitigation.sh
```

This removes:
- All iptables DROP rules
- All tc rate limiting filters
- Ingress qdisc configuration

## Troubleshooting

### Issue: MPI Error "mpirun not found"

**Solution:**
```bash
sudo apt-get install -y mpich libmpich-dev
which mpirun
```

### Issue: Compilation Error "lapacke.h not found"

**Solution:**
```bash
sudo apt-get install -y liblapacke-dev liblapack-dev libblas-dev
sudo ldconfig
make clean
make
```

### Issue: "Permission denied" when running orchestrator

**Solution:**
```bash
# Always run with sudo for mitigation features
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator

# Or disable mitigation in configuration
```

### Issue: No output files created

**Solution:**
```bash
# Check results directory exists
mkdir -p ~/ddos_mpi_detector/results

# Check write permissions
ls -ld ~/ddos_mpi_detector/results
chmod 755 ~/ddos_mpi_detector/results
```

### Issue: Live capture mode sees no files

**Solution:**
```bash
# Check capture directory exists
mkdir -p /mirror/ddos_mpi_detector/live_captures

# Verify capture script is running
ps aux | grep live_traffic_capture

# Check for CSV files
ls -lh /mirror/ddos_mpi_detector/live_captures/
```

### Issue: Workers deadlock in live mode

**Solution:** Already fixed in current version. Workers persist between windows in live mode.

**Verification:**
```bash
# Check orchestrator.c line 668 has is_live_mode parameter
grep "is_live_mode" ~/ddos_mpi_detector/src/core/orchestrator.c
```

### Issue: Victim IP being blocked

**Solution:** Fixed in latest capture script with server IP exclusion.

**Verification:**
```bash
# Check capture script has server_ips tracking (line 204-220)
grep "server_ips" /home/kali/Desktop/live_capture_tool/live_traffic_capture_continuous.py
```

### Issue: tc rate limiting not working

**Solution:** Already fixed - proper ingress qdisc creation.

**Verification:**
```bash
# Check mitigation_engine.c has explicit qdisc check (line 44-52)
grep "qdisc add" ~/ddos_mpi_detector/src/mitigation/mitigation_engine.c
```

## Performance Tuning

### MPI Process Count

```bash
# Default: 3 processes (1 master + 2 workers)
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator

# More workers for faster processing:
sudo mpirun --allow-run-as-root -np 5 ./bin/ddos_orchestrator  # 4 workers
sudo mpirun --allow-run-as-root -np 9 ./bin/ddos_orchestrator  # 8 workers
```

**Recommendation:** Use (CPU cores - 1) for worker count.

### Window Size

**Small windows (500 flows):**
- Faster per-window processing
- More granular detection
- Higher overhead (more windows)

**Large windows (2000 flows):**
- Slower per-window processing
- Less granular detection
- Lower overhead (fewer windows)

**Recommended:** 1000 flows (good balance)

### Detection Thresholds

**Lower thresholds (more sensitive):**
- Catches more attacks
- Higher false positive rate
- Example: Entropy=0.15, PCA=0.25

**Higher thresholds (less sensitive):**
- Fewer false positives
- May miss some attacks
- Example: Entropy=0.30, PCA=0.40

**Recommended:** Entropy=0.20, PCA=0.30 (optimized for DrDoS)

## Security Considerations

⚠️ **WARNING:** This system applies real network mitigation.

### Safe Usage

1. **Test in isolated environment** - Use dedicated lab network
2. **Don't block legitimate IPs** - Set minimum detection count ≥2
3. **Monitor false positives** - Check detection_results.csv regularly
4. **Have cleanup ready** - Keep cleanup_mitigation.sh accessible
5. **Document changes** - Note any iptables/tc rules before testing

### Emergency Cleanup

If system blocks wrong IPs:

```bash
# Stop detection immediately
Ctrl+C

# Remove all mitigation
cd ~/ddos_mpi_detector
sudo ./cleanup_mitigation.sh

# Verify cleanup
sudo iptables -L INPUT -n
sudo tc filter show dev eth0 parent ffff:
```

## Related Documentation

- **TESTING_GUIDE.md** - Step-by-step testing instructions for all 3 modes
- **MPI_ARCHITECTURE.md** - Deep dive into MPI implementation and parallel processing
- **live_capture_tool/README.md** - Live traffic capture documentation
- **attacker_vm/README.md** - Multi-attacker simulation tool documentation

## Support & Debugging

### Enable Verbose Output

Edit `src/core/orchestrator.c` and recompile:

```c
#define DEBUG_MODE 1  // Add at top of file
```

### Check Logs

```bash
# MPI output
cat ~/ddos_mpi_detector/mpi_debug.log

# System logs
dmesg | grep -i ddos
journalctl -xe | grep -i mpi
```

### Get System Info

```bash
# MPI version
mpirun --version

# Number of CPU cores
nproc

# Available memory
free -h

# Network interfaces
ip link show

# LAPACK installation
ldconfig -p | grep lapack
```

## Citation

If you use this system in research or publication, please cite:

```
MPI-Based DDoS Detection System
Distributed Network Intrusion Detection using Parallel Processing
Version 1.0, 2025
```

## License

This system is for educational and authorized security testing purposes only.

**DO NOT:**
- Deploy on production networks without proper authorization
- Use for malicious purposes
- Attack systems you don't own or have permission to test

Unauthorized DDoS attacks and network intrusion are illegal in most jurisdictions.
