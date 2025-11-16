# Multi-Attacker DDoS Simulation Tool

## Overview

The **Multi-Attacker DDoS Simulation Tool** is a coordinated attack testing platform designed to simulate realistic distributed denial-of-service attacks from multiple source IPs. It supports two attack types (GoldenEye HTTP flood and Slowloris slow HTTP) with configurable intensity levels and durations.

## Features

- **Multiple Attack Types**
  - **GoldenEye**: High-volume HTTP GET/POST flood attacks
  - **Slowloris**: Low-and-slow connection exhaustion attacks

- **Coordinated Multi-Source Attacks**
  - Simulates 1-10 concurrent attacker IPs
  - Staggered launch to mimic real DDoS patterns
  - Configurable intensity per attacker

- **Intelligent Timing**
  - Aligned with 10-second detection capture windows
  - Minimum 20-30 seconds recommended for proper multi-IP detection
  - Real-time attack monitoring with countdown

- **Interactive Configuration**
  - User-friendly menu system
  - Default values for quick testing
  - Intensity presets (Light/Medium/Heavy)

## Prerequisites

### Required Tools

**GoldenEye HTTP Flood Tool:**
```bash
mkdir -p ~/attack_tools
cd ~/attack_tools
git clone https://github.com/jseidl/GoldenEye.git
```

**Slowloris Tool:**
```bash
mkdir -p ~/attack_tools/slowloris
cd ~/attack_tools/slowloris
wget https://raw.githubusercontent.com/gkbrk/slowloris/master/slowloris.py
chmod +x slowloris.py
```

### Python Dependencies

```bash
sudo apt-get install python3
```

## Installation

1. **Copy script to attacker VM:**
```bash
cd ~/
mkdir -p attack_tools
cd attack_tools
# Copy multi_attacker.py to this directory
chmod +x multi_attacker.py
```

2. **Install attack tools** (see Prerequisites above)

## Usage

### Basic Launch

```bash
cd ~/attack_tools
python3 multi_attacker.py
```

### Interactive Configuration

The script will guide you through:

1. **Attack Type Selection**
   - Option 1: GoldenEye (fast, high-volume)
   - Option 2: Slowloris (slow, connection exhaustion)

2. **Target Configuration**
   - Target IP (default: 192.168.10.10)
   - Attack duration in seconds (default: 60s)
   - Number of attacker IPs (default: 3, max: 10)

3. **Intensity Selection**
   - **GoldenEye:**
     - Light: 10 workers per attacker
     - Medium: 25 workers per attacker
     - Heavy: 50 workers per attacker
   - **Slowloris:**
     - Light: 50 connections per attacker
     - Medium: 100 connections per attacker
     - Heavy: 200 connections per attacker

### Example Configuration

```
Target IP: 192.168.10.10
Duration: 60 seconds
Attackers: 6 source IPs
Intensity: Medium (25 workers)
Total Load: 150 concurrent connections
```

## Attack Workflow

### On Attacker VM (192.168.10.20)

```bash
cd ~/attack_tools
python3 multi_attacker.py

# Follow prompts:
# 1. Select attack type (GoldenEye or Slowloris)
# 2. Enter target IP: 192.168.10.10
# 3. Enter duration: 60
# 4. Enter attackers: 6
# 5. Select intensity: 2 (Medium)
# 6. Wait for setup confirmation
# 7. Attack launches automatically
```

### On Target VM (192.168.10.10)

**Terminal 1 - Web Server:**
```bash
# For GoldenEye attacks:
sudo python3 -m http.server 80

# For Slowloris attacks:
sudo systemctl start apache2
```

**Terminal 2 - Traffic Capture:**
```bash
cd /home/kali/Desktop/live_capture_tool
sudo python3 live_traffic_capture_continuous.py -i eth0 \
    -o /mirror/ddos_mpi_detector/live_captures
```

**Terminal 3 - DDoS Detection:**
```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
# Select Option 3 (Live Capture)
# Enable mitigation: y
```

## Attack Coordination

### Timing Information

- **Capture Window**: 10 seconds (default)
- **Detection Latency**: 2-3 windows (20-30 seconds)
- **Minimum Duration**: 20-30 seconds for reliable multi-IP capture
- **Recommended Duration**: 60-120 seconds for full testing

### IP Distribution

The script simulates attacks from multiple IPs:
- Attacker 1: 192.168.10.20
- Attacker 2: 192.168.10.21
- Attacker 3: 192.168.10.22
- ... up to 192.168.10.29 (max 10 attackers)

**Note:** All processes run on the same VM, so traffic originates from a single source IP (192.168.10.20) unless IP spoofing is configured.

## Real-Time Monitoring

During attack execution, the script displays:

```
[045s] Active attackers: 6/6 | Remaining: 015s
```

- **Elapsed time**: Seconds since attack start
- **Active attackers**: Number of running attack processes
- **Remaining time**: Seconds until automatic stop

## Attack Termination

### Automatic Stop
- Attack stops automatically after configured duration
- All processes terminated gracefully
- Summary displayed with statistics

### Manual Stop
```
Press Ctrl+C during attack
```

All attacker processes will be terminated immediately.

## Verification & Results

### Check Detection Results

**On Target VM:**

```bash
# View detection results
cat ~/ddos_mpi_detector/results/detection_results.csv

# Check blocked IPs
cat ~/ddos_mpi_detector/results/merged_blocklist.csv

# View iptables rules
sudo iptables -L INPUT -n -v

# View tc rate limiting
sudo tc filter show dev eth0 parent ffff:
```

### Expected Mitigation Output

```
Processing IP: 192.168.10.20 (detections: 1)
  [✓] Blocked IP: 192.168.10.20
  [✓] Rate limited IP: 192.168.10.20 to 10 Mbps

Mitigation complete: 1 IPs processed
```

## Troubleshooting

### Issue: "GoldenEye not found"
**Solution:**
```bash
mkdir -p ~/attack_tools
cd ~/attack_tools
git clone https://github.com/jseidl/GoldenEye.git
```

### Issue: "Slowloris not found"
**Solution:**
```bash
mkdir -p ~/attack_tools/slowloris
cd ~/attack_tools/slowloris
wget https://raw.githubusercontent.com/gkbrk/slowloris/master/slowloris.py
chmod +x slowloris.py
```

### Issue: Only 1-2 IPs detected instead of 6
**Explanation:** All attack processes run on the same VM, sharing the source IP (192.168.10.20). For true multi-IP attacks, you need:
- Multiple physical/virtual attacker machines, OR
- IP spoofing using raw packets (Scapy), OR
- Use dataset analysis mode which has real multi-attacker data

### Issue: Attack processes not starting
**Solution:**
```bash
# Check Python version
python3 --version

# Verify tool paths
ls -la ~/attack_tools/GoldenEye/goldeneye.py
ls -la ~/attack_tools/slowloris/slowloris.py

# Check permissions
chmod +x ~/attack_tools/GoldenEye/goldeneye.py
chmod +x ~/attack_tools/slowloris/slowloris.py
```

### Issue: Target VM not responding
**Solution:**
```bash
# Verify connectivity
ping 192.168.10.10

# Check web server
curl http://192.168.10.10

# Restart web server
sudo python3 -m http.server 80
```

## Cleanup

### On Target VM

```bash
cd ~/ddos_mpi_detector
sudo ./cleanup_mitigation.sh
```

This removes:
- All iptables DROP rules
- All tc rate limiting filters
- Resets mitigation state

## Performance Tuning

### For Faster Detection
```bash
# Use shorter capture windows (5 seconds)
sudo python3 live_traffic_capture_continuous.py -i eth0 -d 5 \
    -o /mirror/ddos_mpi_detector/live_captures
```

### For Better IP Diversity
```bash
# Use longer capture windows (15 seconds)
sudo python3 live_traffic_capture_continuous.py -i eth0 -d 15 \
    -o /mirror/ddos_mpi_detector/live_captures
```

### For Heavy Load Testing
```bash
# Launch attack with maximum intensity
# Select Heavy intensity (50 workers or 200 connections)
# Use 10 attackers
# Total: 500-2000 concurrent connections
```

## Technical Details

### Attack Mechanisms

**GoldenEye:**
- Sends rapid HTTP GET/POST requests
- Randomizes User-Agent headers
- Multiple worker threads per attacker
- High packet rate, high bandwidth

**Slowloris:**
- Opens many connections to web server
- Sends partial HTTP headers slowly
- Keeps connections alive indefinitely
- Low bandwidth, resource exhaustion

### Simulated IPs

The script assigns sequential IPs from 192.168.10.20-29 to represent different attackers, though all traffic originates from the attacker VM's actual IP (192.168.10.20).

### Process Management

- Each attacker runs as a separate subprocess
- Processes managed via process groups (PGID)
- Graceful termination with SIGTERM, forced with SIGKILL
- Output redirected to /dev/null for clean console

## Integration with Detection System

### Detection Pipeline

1. **Capture** (live_traffic_capture_continuous.py)
   - Captures packets in 10-second windows
   - Writes CSV files with flow features
   - Marks HTTP flood attacks (50+ connections)

2. **Detection** (ddos_orchestrator)
   - Loads CSV files from capture directory
   - Runs MPI-based entropy and PCA analysis
   - Identifies malicious IPs

3. **Mitigation** (mitigation_engine.c)
   - Blocks detected IPs with iptables
   - Rate limits with tc (10 Mbps)
   - Prevents further attacks

### Expected Detection Timeline

```
T+00s: Attack launched (6 attackers, 150 connections)
T+10s: First capture window completes, CSV written
T+12s: Detection analyzes first window, identifies attack
T+15s: Mitigation applied, attacker IPs blocked
T+20s: Second capture window, attack continues (blocked)
T+60s: Attack stops automatically
```

## Security Considerations

⚠️ **WARNING**: This tool generates real network attacks.

### Legal & Ethical Use

- **ONLY** use on isolated test networks you own
- **NEVER** attack production systems or networks without authorization
- **NEVER** attack systems you don't own or have written permission to test
- Unauthorized DDoS attacks are illegal in most jurisdictions

### Recommended Network Isolation

- Use a dedicated lab network (e.g., 192.168.10.0/24)
- No internet connectivity during testing
- Separate from production networks
- Virtual machines on isolated host-only network

## Version History

- **v1.0.0** - Initial release
  - GoldenEye and Slowloris support
  - Multi-attacker coordination
  - Interactive configuration
  - Real-time monitoring
  - 10-second window alignment

## Support & Documentation

For issues or questions about the DDoS detection system:
1. Check main project README
2. Review detection logs: `~/ddos_mpi_detector/detection.log`
3. Review capture output: `/mirror/ddos_mpi_detector/live_captures/`

## License

This tool is for educational and authorized security testing purposes only.
