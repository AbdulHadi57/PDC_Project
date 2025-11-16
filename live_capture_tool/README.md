# Live Traffic Capture Tool

## Overview

The **Live Traffic Capture Tool** is a continuous packet capture system designed for real-time DDoS detection. It captures network traffic in timed windows, extracts flow features, and writes CSV files compatible with the MPI-based DDoS detection system.

## Features

- **Continuous Capture Mode**
  - Captures packets in configurable time windows (default: 10 seconds)
  - Automatically saves CSV files after each window
  - Runs indefinitely until stopped (Ctrl+C)

- **Flow-Based Analysis**
  - Tracks bidirectional flows using 5-tuple (src_ip, src_port, dst_ip, dst_port, protocol)
  - Extracts 79 flow features matching CIC-DDoS2019 dataset format
  - Calculates per-flow statistics (packet counts, byte counts, rates, flags)

- **Real-Time Attack Detection**
  - **HTTP Flood Detection**: Identifies attacks with 50+ connections to web ports (80/443/8080)
  - **Server IP Exclusion**: Distinguishes legitimate servers from attackers
  - Marks malicious flows with 'Attack' label in CSV

- **Integration with Detection System**
  - Output CSV files directly consumable by MPI-based detector
  - Live capture directory monitored by orchestrator
  - Automatic mitigation when enabled

## Prerequisites

### System Requirements

- **OS**: Linux (Kali, Ubuntu, Debian)
- **Python**: 3.6 or higher
- **Privileges**: Root access (required for packet capture)
- **Network**: Direct access to capture interface (eth0, wlan0, etc.)

### Python Dependencies

```bash
# Install Scapy
sudo apt-get update
sudo apt-get install python3-scapy

# Or using pip
pip3 install scapy
```

## Installation

1. **Create capture tool directory:**
```bash
mkdir -p /home/kali/Desktop/live_capture_tool
cd /home/kali/Desktop/live_capture_tool
```

2. **Copy script:**
```bash
# Copy live_traffic_capture_continuous.py to this directory
chmod +x live_traffic_capture_continuous.py
```

3. **Create output directory:**
```bash
mkdir -p /mirror/ddos_mpi_detector/live_captures
```

## Usage

### Basic Launch

```bash
cd /home/kali/Desktop/live_capture_tool
sudo python3 live_traffic_capture_continuous.py -i eth0 \
    -o /mirror/ddos_mpi_detector/live_captures
```

### Command-Line Options

```bash
sudo python3 live_traffic_capture_continuous.py [OPTIONS]
```

**Required Arguments:**
- `-i, --interface INTERFACE` : Network interface to capture on (e.g., eth0, wlan0)
- `-o, --output OUTPUT_DIR` : Directory to save CSV files

**Optional Arguments:**
- `-d, --duration SECONDS` : Window duration in seconds (default: 10)
- `-h, --help` : Show help message

### Examples

**Standard 10-second windows (recommended for DDoS):**
```bash
sudo python3 live_traffic_capture_continuous.py -i eth0 \
    -o /mirror/ddos_mpi_detector/live_captures
```

**Faster detection with 5-second windows:**
```bash
sudo python3 live_traffic_capture_continuous.py -i eth0 -d 5 \
    -o /mirror/ddos_mpi_detector/live_captures
```

**Better IP diversity with 15-second windows:**
```bash
sudo python3 live_traffic_capture_continuous.py -i eth0 -d 15 \
    -o /mirror/ddos_mpi_detector/live_captures
```

## Output Format

### CSV File Naming

```
live_capture_YYYYMMDD_HHMMSS.csv
```

Example: `live_capture_20250116_143052.csv`

### CSV Structure

**79 Flow Features (CIC-DDoS2019 compatible):**

| Column | Description |
|--------|-------------|
| `src_ip` | Source IP address |
| `src_port` | Source port number |
| `dst_ip` | Destination IP address |
| `dst_port` | Destination port number |
| `protocol` | Protocol number (6=TCP, 17=UDP, 1=ICMP) |
| `flow_duration` | Duration of flow in seconds |
| `fwd_pkts` | Forward packets (src→dst) |
| `bwd_pkts` | Backward packets (dst→src) |
| `fwd_bytes` | Forward bytes |
| `bwd_bytes` | Backward bytes |
| `fwd_pkt_rate` | Forward packet rate (pkts/sec) |
| `bwd_pkt_rate` | Backward packet rate |
| `flow_pkt_rate` | Total packet rate |
| `... (66 more features)` | Statistical features, flags, IAT metrics |
| `label` | 'Benign' or 'Attack' |

### Example Output

```csv
src_ip,src_port,dst_ip,dst_port,protocol,flow_duration,fwd_pkts,bwd_pkts,...,label
192.168.10.20,54321,192.168.10.10,80,6,9.5,127,98,...,Attack
192.168.10.10,443,192.168.10.50,56234,6,8.2,45,42,...,Benign
```

## Attack Detection Logic

### HTTP Flood Detection

The tool automatically identifies HTTP flood attacks using the following logic:

1. **Track Server IPs:**
   - IPs responding FROM port 80/443/8080 are marked as servers
   - Example: 192.168.10.10:80 → 192.168.10.20:54321 (server response)

2. **Count Attack Flows:**
   - Count connections TO port 80/443/8080 per source IP
   - Example: 192.168.10.20:* → 192.168.10.10:80 (attack request)

3. **Apply Threshold:**
   - If source IP has ≥50 connections to web ports: mark as attacker
   - If source IP is a server: exclude from attackers (prevents self-blocking)

4. **Label Flows:**
   - All flows from attacker IPs: labeled 'Attack'
   - All other flows: labeled 'Benign'

### Server IP Exclusion (Critical Fix)

**Without exclusion (buggy behavior):**
```
192.168.10.20 → 192.168.10.10:80  (request)   → count[192.168.10.20]++
192.168.10.10:80 → 192.168.10.20  (response)  → count[192.168.10.10]++
Result: Both marked as attackers! ❌
```

**With exclusion (correct behavior):**
```
192.168.10.10:80 → 192.168.10.20  (response)  → server_ips.add(192.168.10.10)
192.168.10.20 → 192.168.10.10:80  (request)   → count[192.168.10.20]++
Result: Only 192.168.10.20 marked as attacker ✓
```

## Integration with Detection System

### Complete Workflow

**Terminal 1 - Web Server:**
```bash
sudo python3 -m http.server 80
```

**Terminal 2 - Capture (This Tool):**
```bash
cd /home/kali/Desktop/live_capture_tool
sudo python3 live_traffic_capture_continuous.py -i eth0 \
    -o /mirror/ddos_mpi_detector/live_captures
```

**Terminal 3 - Detection:**
```bash
cd ~/ddos_mpi_detector
sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
# Select Option 3 (Live Capture)
# Enable mitigation: y
```

**Terminal 4 - Attack:**
```bash
cd ~/attack_tools
python3 multi_attacker.py
```

### Detection Timeline

```
T+00s: Capture starts, monitoring eth0
T+05s: Attack launched from 192.168.10.20
T+10s: First window completes
        → CSV saved: live_capture_20250116_143052.csv
        → Flows marked: 127 flows from 192.168.10.20 labeled 'Attack'
T+12s: Orchestrator loads CSV, runs detection
        → Entropy: Detects anomaly (high connection rate)
        → PCA: Detects anomaly (unusual flow patterns)
        → Result: 192.168.10.20 identified as attacker
T+15s: Mitigation applied
        → iptables: DROP rule for 192.168.10.20
        → tc: Rate limit 192.168.10.20 to 10 Mbps
T+20s: Second window completes
        → Attacker still blocked
        → New flows from attacker dropped at firewall
T+30s: Attack stops, capture continues
```

## Real-Time Monitoring

### Capture Output

```
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║       Continuous Live Traffic Capture Tool              ║
║       Real-time packet capture for DDoS detection       ║
║                                                            ║
║       Version: 1.0.0                                    ║
╚════════════════════════════════════════════════════════════╝

[+] Starting continuous capture...
[+] Interface: eth0
[+] Output: /mirror/ddos_mpi_detector/live_captures
[+] Window: 10 seconds
[+] Press Ctrl+C to stop

[Window 1] Capturing...
  ├─ Packets: 2,547
  ├─ Flows: 198
  ├─ Duration: 10.0s
  └─ Saved: live_capture_20250116_143052.csv
```

### During Attack

```
[Window 2] Capturing...
  ├─ Packets: 15,432
  ├─ Flows: 1,247
  ├─ HTTP Flood Detected!
  │    └─ Attacker: 192.168.10.20 (127 connections)
  ├─ Duration: 10.0s
  └─ Saved: live_capture_20250116_143102.csv
```

## Performance Tuning

### Window Duration Selection

| Duration | Pros | Cons | Best For |
|----------|------|------|----------|
| **5s** | Faster detection (10-15s) | Fewer IPs per window | Single-source attacks |
| **10s** | Balanced (20-30s) | Good IP diversity | Multi-attacker DDoS (recommended) |
| **15s** | Better IP diversity | Slower detection (30-45s) | Low-volume distributed attacks |

### Network Interface Selection

```bash
# List available interfaces
ip link show

# Common interfaces:
# eth0     - Wired Ethernet
# wlan0    - Wireless
# ens33    - VMware virtual
# enp0s3   - VirtualBox virtual
```

### Output Directory

**Recommended structure:**
```
/mirror/
  └─ ddos_mpi_detector/
      ├─ live_captures/        ← Capture output (this tool)
      │   ├─ live_capture_20250116_143052.csv
      │   ├─ live_capture_20250116_143102.csv
      │   └─ ...
      ├─ results/              ← Detection output
      │   ├─ detection_results.csv
      │   ├─ merged_blocklist.csv
      │   └─ entropy_blocklist.csv
      └─ logs/
          └─ detection.log
```

## Troubleshooting

### Issue: "Permission denied" or "Operation not permitted"
**Solution:**
```bash
# Always run with sudo
sudo python3 live_traffic_capture_continuous.py -i eth0 \
    -o /mirror/ddos_mpi_detector/live_captures
```

### Issue: "Error: scapy not installed"
**Solution:**
```bash
sudo apt-get update
sudo apt-get install python3-scapy

# Verify installation
python3 -c "from scapy.all import sniff; print('Scapy OK')"
```

### Issue: No packets captured
**Solution:**
```bash
# Check interface is up
ip link show eth0

# Bring interface up if down
sudo ip link set eth0 up

# Verify packets on interface
sudo tcpdump -i eth0 -c 10

# Check promiscuous mode (should be enabled automatically)
sudo ifconfig eth0 promisc
```

### Issue: Interface not found
**Solution:**
```bash
# List all interfaces
ip link show

# Use correct interface name
sudo python3 live_traffic_capture_continuous.py -i ens33 \
    -o /mirror/ddos_mpi_detector/live_captures
```

### Issue: Output directory permission denied
**Solution:**
```bash
# Create directory with sudo
sudo mkdir -p /mirror/ddos_mpi_detector/live_captures

# Fix permissions
sudo chown -R $USER:$USER /mirror/ddos_mpi_detector

# Or run capture as root
sudo python3 live_traffic_capture_continuous.py ...
```

### Issue: No flows in CSV (empty files)
**Solution:**
```bash
# Generate some traffic
ping 8.8.8.8

# Or browse a website
curl http://example.com

# Check interface has traffic
sudo tcpdump -i eth0 -c 100
```

### Issue: Victim IP being blocked (self-blocking)
**Explanation:** Server responses counted as attacks in older versions.

**Solution:** Update to latest version with server IP exclusion fix (lines 204-220).

### Issue: Only seeing 1-2 IPs in multi-attacker tests
**Explanation:** All attack tools run on same VM, share source IP.

**Solution:** For true multi-IP testing:
- Use dataset analysis mode (has real multi-IP data)
- Deploy multiple attacker VMs
- Implement IP spoofing with Scapy

## Technical Details

### Flow Tracking

**5-Tuple Flow Key:**
```python
(src_ip, src_port, dst_ip, dst_port, protocol)
```

**Bidirectional Flow:**
- Forward: Packets from src→dst
- Backward: Packets from dst→src
- Same flow: (A,1000,B,80,TCP) and (B,80,A,1000,TCP)

### Feature Extraction

**Packet-Level Features:**
- Packet counts (forward, backward, total)
- Byte counts (forward, backward, total)
- Packet rates (packets per second)
- Byte rates (bytes per second)

**Flow-Level Features:**
- Flow duration (time between first and last packet)
- Inter-arrival times (IAT) - mean, std, max, min
- Packet size statistics - mean, std, max, min
- TCP flags (SYN, ACK, FIN, RST, PSH, URG)
- Initial window size (forward, backward)

**Protocol Statistics:**
- Protocol distribution (TCP/UDP/ICMP)
- Port numbers (source, destination)
- Active time (time with actual data transfer)
- Idle time (time without packets)

### Memory Management

- Flows cleared after each window
- Dictionary-based flow storage
- Lock-based thread safety
- Automatic memory reclamation

### Signal Handling

- Graceful shutdown on Ctrl+C
- Saves final window before exit
- Terminates capture immediately
- Force exit on second Ctrl+C

## Security Considerations

### Ethical Use

⚠️ **WARNING**: This tool captures all network traffic on the interface.

- **Privacy**: May capture sensitive data (passwords, tokens, etc.)
- **Legal**: Packet capture may be restricted in some jurisdictions
- **Ethical**: Only capture traffic on networks you own or have permission to monitor

### Best Practices

1. **Isolated Networks**: Use dedicated test networks (e.g., 192.168.10.0/24)
2. **No Production Data**: Never capture production traffic without authorization
3. **Secure Storage**: Protect CSV files containing network data
4. **Cleanup**: Delete captures after testing

### Data Sanitization

If sharing CSV files:
```bash
# Remove sensitive IPs
sed 's/192\.168\.10\./XXX.XXX.XXX./g' live_capture_*.csv

# Remove port numbers
cut -d',' -f1,3,5- live_capture_*.csv
```

## Integration APIs

### CSV Schema

The tool outputs CSV files compatible with:
- CIC-DDoS2019 dataset format
- MPI-based DDoS orchestrator
- Standard flow-based ML models
- Network traffic analysis tools

### Programmatic Access

```python
import pandas as pd

# Load capture
df = pd.read_csv('/mirror/ddos_mpi_detector/live_captures/live_capture_20250116_143052.csv')

# Filter attacks
attacks = df[df['label'] == 'Attack']

# Get attacker IPs
attacker_ips = attacks['src_ip'].unique()
print(f"Detected attackers: {attacker_ips}")
```

## Performance Metrics

### Capture Rates

| Network Load | Packets/sec | Flows/window | CSV Size |
|--------------|-------------|--------------|----------|
| **Idle** | ~100 | 50-100 | ~50 KB |
| **Normal** | ~1,000 | 200-500 | ~200 KB |
| **Attack** | ~10,000 | 1,000-2,000 | ~1 MB |
| **Heavy Attack** | ~50,000 | 5,000+ | ~5 MB |

### Resource Usage

- **CPU**: 5-15% per capture process
- **Memory**: ~50-200 MB (depends on flow count)
- **Disk I/O**: ~1-5 MB/window (10s)
- **Network**: Promiscuous mode (all packets)

## Version History

- **v1.0.0** - Initial release
  - Continuous capture mode
  - 10-second windows
  - 79 flow features
  - Basic attack detection

- **v1.1.0** - Server IP exclusion fix
  - Prevents victim IP self-blocking
  - Distinguishes servers from attackers
  - HTTP flood detection improvements

## Related Tools

- **ddos_orchestrator**: MPI-based detection engine
- **multi_attacker.py**: Coordinated attack simulator
- **mitigation_engine.c**: iptables/tc mitigation
- **cleanup_mitigation.sh**: Cleanup script

## Support

For issues or questions:
1. Check main project README
2. Review detection logs
3. Verify network connectivity
4. Test with simple ping/curl traffic

## License

This tool is for educational and authorized security testing purposes only.
