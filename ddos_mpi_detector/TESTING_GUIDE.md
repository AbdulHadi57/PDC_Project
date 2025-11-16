# Testing Guide for DDoS Detection System

## Overview

This guide provides step-by-step instructions for testing all three operating modes of the MPI-based DDoS detection system, including mitigation verification using iptables and tc (traffic control).

## Table of Contents

1. [Pre-Testing Setup](#pre-testing-setup)
2. [Mode 1: Quick Start Testing](#mode-1-quick-start-testing)
3. [Mode 2: Dataset Analysis Testing](#mode-2-dataset-analysis-testing)
4. [Mode 3: Live Capture Testing](#mode-3-live-capture-testing)
5. [Mitigation Verification](#mitigation-verification)
6. [Performance Testing](#performance-testing)
7. [Troubleshooting](#troubleshooting)

---

## Pre-Testing Setup

### 1. Verify System Requirements

```bash
# Check MPI installation
mpirun --version
# Expected: MPICH Version 3.3+

# Check compilation
cd ~/ddos_mpi_detector
ls -lh bin/ddos_orchestrator
# Expected: ELF 64-bit executable

# Check dataset availability
ls -lh /mirror/dataset/01-12/
# Expected: DrDoS_DNS.csv, DrDoS_NTP.csv, etc.
```

### 2. Create Required Directories

```bash
# Results directory
mkdir -p ~/ddos_mpi_detector/results

# Live capture directory
sudo mkdir -p /mirror/ddos_mpi_detector/live_captures
sudo chown -R $USER:$USER /mirror/ddos_mpi_detector
```

### 3. Clean Previous State

```bash
cd ~/ddos_mpi_detector

# Remove old results
rm -f results/*.csv

# Clean mitigation rules
sudo ./cleanup_mitigation.sh
```

### 4. Verify Network Interface

```bash
# List interfaces
ip link show

# Common interface names:
# - eth0 (wired Ethernet)
# - wlan0 (wireless)
# - ens33 (VMware)
# - enp0s3 (VirtualBox)

# Export your interface for later use
export TEST_INTERFACE="eth0"
echo "Using interface: $TEST_INTERFACE"
```

---

## Mode 1: Quick Start Testing

### Objective

Verify basic functionality with default settings on DrDoS_DNS dataset.

### Test Steps

**Step 1: Launch System**

```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
```

**Step 2: Select Quick Start**

```
Enter choice [0-3]: 1
```

**Step 3: Observe Output**

Expected output sequence:

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
Window 150/150 | Entropy: ✓ Attack  | PCA: ✓ Attack  | CUSUM: ✓ Attack  | Final: Attack

Analysis Complete!
  Windows processed: 150
  Attack windows: 148 (98.67%)
  Benign windows: 2 (1.33%)

Performance Metrics:
  Processing time: 12.3 seconds
  Average per window: 82 ms
  Throughput: 12,195 flows/second

Detection Accuracy:
  True Positives: 148
  True Negatives: 2
  False Positives: 0
  False Negatives: 0
  Accuracy: 99.98%
  Precision: 100.00%
  Recall: 100.00%
  F1 Score: 100.00%

Results saved to: ~/ddos_mpi_detector/results/
```

**Step 4: Verify Output Files**

```bash
# Check detection results
ls -lh ~/ddos_mpi_detector/results/
# Expected files:
# - detection_results.csv
# - entropy_blocklist.csv
# - pca_blocklist.csv
# - merged_blocklist.csv

# View first 10 windows
head -n 11 ~/ddos_mpi_detector/results/detection_results.csv

# Count attack windows
grep ",1,1,1,1,1," ~/ddos_mpi_detector/results/detection_results.csv | wc -l
# Expected: ~148 windows

# Check blocklist
cat ~/ddos_mpi_detector/results/merged_blocklist.csv
# Expected: Multiple attacker IPs with detection counts
```

**Step 5: Verify No Mitigation Applied**

```bash
# Check iptables (should be empty)
sudo iptables -L INPUT -n | grep DROP
# Expected: No output (Quick Start doesn't enable mitigation)

# Check tc filters (should be empty)
sudo tc filter show dev $TEST_INTERFACE parent ffff:
# Expected: No output
```

### Expected Results

✅ **Pass Criteria:**
- System completes without errors
- 150 windows processed
- Accuracy ≥99%
- 4 CSV files created in results/
- No mitigation rules applied

❌ **Failure Indicators:**
- Segmentation fault
- MPI deadlock (hangs indefinitely)
- Accuracy <90%
- Missing output files

---

## Mode 2: Dataset Analysis Testing

### Objective

Test custom configuration and automated mitigation on dataset.

### Test Scenario 1: Basic Dataset Analysis (No Mitigation)

**Step 1: Launch System**

```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
```

**Step 2: Select Dataset Analysis**

```
Enter choice [0-3]: 2
```

**Step 3: Configure Parameters**

```
Dataset file path
  Enter path: /mirror/dataset/01-12/DrDoS_NTP.csv

Window size (flows per window)
  Enter size: [Press Enter for default 1000]

Entropy detection threshold
  Enter threshold: [Press Enter for default 0.20]

PCA detection threshold
  Enter threshold: [Press Enter for default 0.30]

Enable automated mitigation? (y/N): n
```

**Step 4: Verify Results**

```bash
# Check processing completed
ls -lh ~/ddos_mpi_detector/results/detection_results.csv

# View summary statistics
tail -n 20 ~/ddos_mpi_detector/results/detection_results.csv

# Verify DrDoS_NTP attacks detected
grep -c ",1,1,1,1,1," ~/ddos_mpi_detector/results/detection_results.csv
# Expected: >90% of windows
```

### Test Scenario 2: Dataset Analysis with Mitigation

**Step 1: Clean Previous State**

```bash
sudo ./cleanup_mitigation.sh
rm -f results/*.csv
```

**Step 2: Launch with Mitigation Enabled**

```bash
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
```

**Step 3: Configure with Mitigation**

```
Enter choice [0-3]: 2

Dataset file path: [Enter for default DrDoS_DNS.csv]

Window size: [Enter for default]

Entropy threshold: [Enter for default]

PCA threshold: [Enter for default]

Enable automated mitigation? (y/N): y

Network interface (default: eth0): [Enter or specify interface]

Minimum detection count (default: 1): 2

Enable IP blocking with iptables? (Y/n): y

Enable rate limiting with tc? (Y/n): y

Rate limit (default: 10mbit): [Enter]

Rate burst (default: 100k): [Enter]
```

**Step 4: Observe Mitigation Application**

Expected output after detection:

```
Applying mitigation to detected attackers...

Processing IP: 192.168.50.1 (detections: 2)
  [✓] Blocked IP: 192.168.50.1
  [✓] Rate limited IP: 192.168.50.1 to 10 Mbps

Processing IP: 192.168.50.2 (detections: 3)
  [✓] Blocked IP: 192.168.50.2
  [✓] Rate limited IP: 192.168.50.2 to 10 Mbps

...

Mitigation complete:
  IPs processed: 27
  IPs blocked: 27
  IPs rate-limited: 27
  Processing time: 1.2 seconds
```

**Step 5: Verify Mitigation Rules**

See [Mitigation Verification](#mitigation-verification) section below.

### Expected Results

✅ **Pass Criteria:**
- Custom dataset loaded successfully
- Different attack patterns detected (NTP vs DNS)
- Mitigation applied when enabled
- Minimum detection count respected (only IPs with ≥2 detections blocked)

---

## Mode 3: Live Capture Testing

### Objective

Test real-time detection and mitigation with live network traffic.

### Prerequisites

**On Victim VM (192.168.10.10):**
- Web server running
- Traffic capture script running
- Detection system ready

**On Attacker VM (192.168.10.20):**
- Multi-attacker script installed
- GoldenEye or Slowloris tools ready

### Test Scenario 1: Live Detection without Mitigation

**Terminal 1 (Victim) - Web Server:**

```bash
sudo python3 -m http.server 80
```

**Terminal 2 (Victim) - Traffic Capture:**

```bash
cd /home/kali/Desktop/live_capture_tool
sudo python3 live_traffic_capture_continuous.py -i $TEST_INTERFACE \
    -o /mirror/ddos_mpi_detector/live_captures
```

Wait for output:
```
[+] Starting continuous capture...
[+] Interface: eth0
[+] Output: /mirror/ddos_mpi_detector/live_captures
[+] Window: 10 seconds
[+] Press Ctrl+C to stop

[Window 1] Capturing...
  ├─ Packets: 127
  ├─ Flows: 45
  ├─ Duration: 10.0s
  └─ Saved: live_capture_20250116_143052.csv
```

**Terminal 3 (Victim) - Detection:**

```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
```

Configure:
```
Enter choice [0-3]: 3

Live capture directory: [Enter for default]

Enable automated mitigation? (y/N): n
```

Expected output:
```
[Live Capture Mode] Monitoring: /mirror/ddos_mpi_detector/live_captures
Polling every 1 second...
Press Ctrl+C to stop...

Waiting for capture files...
```

**Terminal 4 (Attacker) - Launch Attack:**

```bash
cd ~/attack_tools
python3 multi_attacker.py
```

Configure attack:
```
Enter choice [0-2]: 1  (GoldenEye)
Target IP: 192.168.10.10
Duration: 60
Attackers: 3
Intensity: 2 (Medium)
```

**Expected Detection Output (Terminal 3):**

```
[10:45:32] New capture file: live_capture_20250116_104522.csv
           Loading 234 flows...
           
           Window 1 | Entropy: ✓ Attack (0.85) | PCA: ✓ Attack (0.72) | CUSUM: ✓ Attack (7.3)
           Combined: Attack
           
           Suspicious IPs:
             - 192.168.10.20 (127 flows, HTTP flood detected)

[10:45:42] New capture file: live_capture_20250116_104532.csv
           Loading 1,547 flows...
           
           Window 2 | Entropy: ✓ Attack (0.92) | PCA: ✓ Attack (0.88) | CUSUM: ✓ Attack (12.8)
           Combined: Attack
           
           Suspicious IPs:
             - 192.168.10.20 (1,398 flows)

[10:45:52] New capture file: live_capture_20250116_104542.csv
...
```

**Stop Test:**

```bash
# Terminal 4: Stop attack (or wait 60 seconds)
Ctrl+C

# Terminal 3: Stop detection
Ctrl+C

# Terminal 2: Stop capture
Ctrl+C
```

### Test Scenario 2: Live Detection with Mitigation

**Repeat setup from Scenario 1, but enable mitigation:**

**Terminal 3 (Victim) - Detection with Mitigation:**

```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
```

Configure:
```
Enter choice [0-3]: 3

Live capture directory: [Enter]

Enable automated mitigation? (y/N): y

Network interface: [Enter for eth0]

Minimum detection count: 1

Enable iptables: y

Enable tc: y

Rate limit: [Enter for 10mbit]
```

**Launch attack from Terminal 4**

**Expected Output:**

```
[10:50:12] New capture file: live_capture_20250116_105002.csv
           Loading 234 flows...
           
           Window 1 | Detection: Attack
           Suspicious IPs: 192.168.10.20

[10:50:22] New capture file: live_capture_20250116_105012.csv
           Loading 1,547 flows...
           
           Window 2 | Detection: Attack
           Suspicious IPs: 192.168.10.20 (2 detections total)

Applying mitigation...
  [✓] Blocked IP: 192.168.10.20
  [✓] Rate limited IP: 192.168.10.20 to 10 Mbps

[10:50:32] New capture file: live_capture_20250116_105022.csv
           Loading 842 flows...
           
           Window 3 | Detection: Benign (attacker blocked at firewall)
```

**Verify Mitigation:**

See [Mitigation Verification](#mitigation-verification) section.

### Expected Results

✅ **Pass Criteria:**
- Capture creates new CSV files every 10 seconds
- Detection processes each file within 1-2 seconds
- Attack detected within 10-20 seconds of launch
- Mitigation applied immediately after detection
- Attack traffic drops after mitigation
- Only attacker IP blocked (not victim 192.168.10.10)

❌ **Failure Indicators:**
- CSV files not created
- Detection doesn't process new files
- Workers deadlock after first window
- Victim IP (192.168.10.10) blocked
- tc filters not applied

---

## Mitigation Verification

### Verify iptables Blocking

**Check Current Rules:**

```bash
sudo iptables -L INPUT -n -v
```

**Expected Output:**

```
Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination
    0     0 DROP       all  --  *      *       192.168.10.20        0.0.0.0/0
```

**Key Points:**
- Target: DROP (complete block)
- Source: Attacker IP (e.g., 192.168.10.20)
- Destination: 0.0.0.0/0 (all destinations)

**Count Blocked IPs:**

```bash
sudo iptables -L INPUT -n | grep DROP | wc -l
# Expected: Number of attacker IPs detected
```

**Test Effectiveness:**

From attacker VM:
```bash
# Before mitigation (should succeed)
ping 192.168.10.10
# Expected: Reply from 192.168.10.10

# After mitigation (should fail)
ping 192.168.10.10
# Expected: No reply, 100% packet loss
```

### Verify tc Rate Limiting

**Check Current Filters:**

```bash
sudo tc filter show dev $TEST_INTERFACE parent ffff:
```

**Expected Output:**

```
filter protocol ip pref 1 u32 chain 0
filter protocol ip pref 1 u32 chain 0 fh 800: ht divisor 1
filter protocol ip pref 1 u32 chain 0 fh 800::800 order 2048 key ht 800 bkt 0 flowid :1 not_in_hw
  match c0a80a14/ffffffff at 12
        police 0x1 rate 10Mbit burst 100Kb mtu 64Kb action drop overhead 0b linklayer ethernet
        ref 1 bind 1
```

**Decode Output:**
- `match c0a80a14/ffffffff`: Hexadecimal IP (c0a80a14 = 192.168.10.20)
- `police 0x1 rate 10Mbit`: Rate limit to 10 Mbps
- `burst 100Kb`: Burst size
- `action drop`: Drop excess packets

**Count Rate-Limited IPs:**

```bash
sudo tc filter show dev $TEST_INTERFACE parent ffff: | grep "match" | wc -l
# Expected: Number of attacker IPs
```

**Check Ingress qdisc:**

```bash
sudo tc qdisc show dev $TEST_INTERFACE
```

**Expected:**
```
qdisc ingress ffff: parent ffff:fff1 ----------------
```

**Test Rate Limiting:**

From attacker VM (requires iperf3):
```bash
# Generate high-bandwidth traffic
iperf3 -c 192.168.10.10 -t 10 -b 50M

# Expected result:
# - Before mitigation: 50 Mbps throughput
# - After mitigation: ~10 Mbps throughput (rate limited)
```

### Verify Combined Mitigation

**Full Status Check:**

```bash
echo "═══ iptables Status ═══"
sudo iptables -L INPUT -n -v | grep DROP

echo ""
echo "═══ tc Filters Status ═══"
sudo tc filter show dev $TEST_INTERFACE parent ffff: | grep -A 2 "match"

echo ""
echo "═══ Summary ═══"
IPTABLES_COUNT=$(sudo iptables -L INPUT -n | grep DROP | wc -l)
TC_COUNT=$(sudo tc filter show dev $TEST_INTERFACE parent ffff: 2>/dev/null | grep "match" | wc -l)
echo "IPs blocked with iptables: $IPTABLES_COUNT"
echo "IPs rate-limited with tc: $TC_COUNT"
```

**Expected:**
- Both counts should match
- Each attacker IP should have both iptables and tc rules

### Verify Minimum Detection Count

**Test with min_count = 2:**

```bash
# Check merged blocklist
cat ~/ddos_mpi_detector/results/merged_blocklist.csv
```

**Expected:**
- Only IPs with detection_count ≥ 2 appear in blocklist
- IPs detected only once are NOT blocked

**Example:**
```csv
ip_address,detection_count,last_detected
192.168.10.20,5,2025-01-16 10:45:42    ← Blocked (count ≥ 2)
192.168.10.21,1,2025-01-16 10:45:32    ← NOT blocked (count < 2)
```

### Test Cleanup

**Remove All Mitigation Rules:**

```bash
cd ~/ddos_mpi_detector
sudo ./cleanup_mitigation.sh
```

**Expected Output:**

```
═══════════════════════════════════════════════════════════
  DDoS Mitigation Cleanup Tool
═══════════════════════════════════════════════════════════

[1] Current iptables DROP rules: 1
    Removing all INPUT chain DROP rules...
    ✓ iptables INPUT chain flushed

[2] Current tc filters on eth0: 1
    Removing all tc filters...
    ✓ tc filters removed

[3] Removing ingress qdisc...
    ✓ Ingress qdisc removed

═══════════════════════════════════════════════════════════
  Verification
═══════════════════════════════════════════════════════════

[✓] iptables INPUT chain:
    ✓ Clean (0 DROP rules)

[✓] tc filters on eth0:
    ✓ Clean (0 filters)

═══════════════════════════════════════════════════════════
  Cleanup Complete!
═══════════════════════════════════════════════════════════
```

**Verify Cleanup:**

```bash
# Check iptables (should be empty)
sudo iptables -L INPUT -n | grep DROP
# Expected: No output

# Check tc (should be empty)
sudo tc filter show dev $TEST_INTERFACE parent ffff:
# Expected: No output

# Test connectivity restored
ping 192.168.10.10
# Expected: Successful ping
```

---

## Performance Testing

### Throughput Test

**Objective:** Measure flows processed per second.

```bash
# Test with large dataset
cd ~/ddos_mpi_detector
time sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator

# Select Mode 1 (Quick Start)
# Note "Total flows analyzed" and "Processing time"

# Calculate throughput:
# Throughput = Total flows / Processing time
# Example: 150,000 flows / 12.3 seconds = 12,195 flows/sec
```

**Expected Performance:**
- 10,000-15,000 flows/second (3 MPI processes)
- 20,000-30,000 flows/second (5 MPI processes)
- 40,000-60,000 flows/second (9 MPI processes)

### Scalability Test

**Test with different MPI process counts:**

```bash
# 3 processes (2 workers)
time sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator

# 5 processes (4 workers)
time sudo mpirun --allow-run-as-root -np 5 ./bin/ddos_orchestrator

# 9 processes (8 workers)
time sudo mpirun --allow-run-as-root -np 9 ./bin/ddos_orchestrator
```

**Expected Speedup:**
- 2 workers: Baseline (12 seconds)
- 4 workers: 1.7-1.9x faster (~7 seconds)
- 8 workers: 2.5-3.5x faster (~4 seconds)

### Latency Test (Live Mode)

**Objective:** Measure detection latency from attack start to mitigation.

```bash
# Record timestamps during live test:
ATTACK_START=$(date +%s)
# Launch attack
# Wait for mitigation message
MITIGATION_TIME=$(date +%s)

# Calculate latency
echo "Detection latency: $((MITIGATION_TIME - ATTACK_START)) seconds"
```

**Expected Latency:**
- First window: 10-12 seconds (capture window + processing)
- Second window: 20-22 seconds
- Mitigation applied: 20-30 seconds total

---

## Troubleshooting

### Test Failure: Accuracy < 99%

**Possible Causes:**
1. Wrong dataset file
2. Incorrect thresholds
3. Corrupted CSV data

**Solution:**
```bash
# Verify dataset integrity
wc -l /mirror/dataset/01-12/DrDoS_DNS.csv
# Expected: ~150,000 lines

# Check for CSV errors
head -n 100 /mirror/dataset/01-12/DrDoS_DNS.csv | less

# Try with known-good dataset
# Use Mode 1 (Quick Start) with default file
```

### Test Failure: MPI Deadlock

**Symptoms:** System hangs, no progress after "Starting distributed analysis..."

**Solution:**
```bash
# Kill hung processes
pkill -9 ddos_orchestrator
pkill -9 mpirun

# Check MPI version
mpirun --version
# Must be MPICH 3.3+

# Verify no zombie processes
ps aux | grep mpi

# Recompile
cd ~/ddos_mpi_detector
make clean
make

# Retry with verbose output
sudo mpirun --allow-run-as-root -np 3 -verbose ./bin/ddos_orchestrator
```

### Test Failure: No Mitigation Applied

**Symptoms:** Detection succeeds but no iptables/tc rules created.

**Solution:**
```bash
# Check root privileges
whoami
# Must show: root (when using sudo)

# Check interface name
ip link show
# Use correct interface in configuration

# Test manual mitigation
sudo iptables -I INPUT -s 192.168.10.20 -j DROP
sudo iptables -L INPUT -n | grep 192.168.10.20
# If manual works, issue is in mitigation_engine.c

# Check mitigation code
grep "system(" ~/ddos_mpi_detector/src/mitigation/mitigation_engine.c
# Should NOT contain "2>/dev/null"

# Recompile if needed
make clean
make
```

### Test Failure: Victim IP Blocked

**Symptoms:** 192.168.10.10 (victim) appears in blocklist.

**Solution:**
```bash
# Check capture script version
grep "server_ips" /home/kali/Desktop/live_capture_tool/live_traffic_capture_continuous.py
# Should have server IP exclusion logic (lines 204-220)

# If missing, update capture script with latest version

# Verify fix
sudo python3 live_traffic_capture_continuous.py -i eth0 -o /mirror/ddos_mpi_detector/live_captures
# Launch small attack, check CSV for victim IP
tail -n 20 /mirror/ddos_mpi_detector/live_captures/*.csv | grep "192.168.10.10"
# Victim flows should be labeled "Benign"
```

---

## Test Completion Checklist

### Mode 1: Quick Start
- [ ] System launches without errors
- [ ] 150 windows processed
- [ ] Accuracy ≥ 99%
- [ ] 4 CSV files created
- [ ] No mitigation applied

### Mode 2: Dataset Analysis
- [ ] Custom dataset loaded
- [ ] Configurable parameters work
- [ ] Mitigation applies correctly
- [ ] iptables rules created
- [ ] tc filters created
- [ ] Minimum detection count respected

### Mode 3: Live Capture
- [ ] Capture creates CSV files every 10 seconds
- [ ] Detection processes files continuously
- [ ] Attack detected within 20-30 seconds
- [ ] Mitigation applied automatically
- [ ] Only attacker IP blocked (not victim)
- [ ] Workers persist between windows (no deadlock)

### Mitigation Verification
- [ ] iptables DROP rules visible
- [ ] tc rate limiting filters visible
- [ ] Ping blocked from attacker
- [ ] Bandwidth limited to 10 Mbps
- [ ] Cleanup script removes all rules

### Performance
- [ ] Throughput ≥ 10,000 flows/second
- [ ] Detection latency ≤ 30 seconds (live mode)
- [ ] No memory leaks (check with `top` during testing)

---

## Next Steps

After successful testing:

1. **Review Results:** Analyze detection_results.csv for insights
2. **Tune Parameters:** Adjust thresholds based on your network
3. **Deploy Production:** Set up continuous live monitoring
4. **Monitor Performance:** Track false positives and detection latency
5. **Document Changes:** Keep notes on configuration tweaks

## Additional Resources

- **README.md** - System overview and installation
- **MPI_ARCHITECTURE.md** - MPI implementation details
- **live_capture_tool/README.md** - Capture tool documentation
- **attacker_vm/README.md** - Attack simulation guide
