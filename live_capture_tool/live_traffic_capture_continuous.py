#!/usr/bin/env python3
"""
Continuous Live Traffic Capture Tool for DDoS Detection
Captures packets and writes CSV files in timed windows for real-time detection
"""

import os
import sys
import time
import signal
import argparse
import csv
import threading
from datetime import datetime
from collections import defaultdict
from pathlib import Path

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: scapy not installed")
    print("Install with: sudo apt-get install python3-scapy")
    sys.exit(1)


class ContinuousCapture:
    """Captures traffic and writes CSV files continuously in timed windows"""
    
    def __init__(self, interface, output_dir, window_duration=10):
        self.interface = interface
        self.output_dir = Path(output_dir)
        self.window_duration = window_duration  # seconds per window (10s default for DDoS)
        
        # Flow tracking
        self.flows = defaultdict(lambda: {
            'first_time': None,
            'last_time': None,
            'fwd_pkts': 0,
            'bwd_pkts': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'src_port': 0,
            'dst_port': 0,
            'protocol': 0,
            'tcp_flags': [],
            'is_attack': False
        })
        
        # Statistics
        self.total_packets = 0
        self.total_flows = 0
        self.window_count = 0
        self.is_running = True
        self.lock = threading.Lock()  # Thread safety
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Window start time
        self.window_start = time.time()
        
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        if not self.is_running:
            # Already stopping, force exit
            print("\n[!] Force stopping...")
            sys.exit(1)
        
        print("\n\n[!] Stopping capture...")
        self.is_running = False
        
        # Give sniff() a moment to stop
        time.sleep(0.5)
        
        # Save any remaining flows
        try:
            with self.lock:
                if self.flows:
                    self.save_current_window()
        except Exception as e:
            print(f"[!] Warning: Error saving final window: {e}")
        
        print(f"\n[✓] Total packets captured: {self.total_packets}")
        print(f"[✓] Total windows saved: {self.window_count}")
        print(f"[✓] Output directory: {self.output_dir}")
        sys.exit(0)
    
    def packet_callback(self, packet):
        """Process each captured packet"""
        if not IP in packet:
            return
        
        with self.lock:
            self.total_packets += 1
            
            src = packet[IP].src
            dst = packet[IP].dst
            timestamp = packet.time
            
            # Extract ports for 5-tuple flow key
            src_port = 0
            dst_port = 0
            proto = packet[IP].proto
            
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Create flow key using 5-tuple (src_ip, src_port, dst_ip, dst_port, proto)
            # This creates separate flows for each unique connection
            key_fwd = (src, src_port, dst, dst_port, proto)
            key_bwd = (dst, dst_port, src, src_port, proto)
            
            # Determine flow direction
            if key_fwd in self.flows:
                key = key_fwd
                direction = 'fwd'
            elif key_bwd in self.flows:
                key = key_bwd
                direction = 'bwd'
            else:
                # New flow
                key = key_fwd
                direction = 'fwd'
            
            flow = self.flows[key]
            
            # Update timestamps
            if flow['first_time'] is None:
                flow['first_time'] = timestamp
            flow['last_time'] = timestamp
            
            # Count packets and bytes
            pkt_len = len(packet)
            if direction == 'fwd':
                flow['fwd_pkts'] += 1
                flow['fwd_bytes'] += pkt_len
            else:
                flow['bwd_pkts'] += 1
                flow['bwd_bytes'] += pkt_len
            
            # Extract layer 4 information
            if TCP in packet:
                if flow['src_port'] == 0:
                    flow['src_port'] = packet[TCP].sport
                    flow['dst_port'] = packet[TCP].dport
                flow['protocol'] = 6
                flow['tcp_flags'].append(packet[TCP].flags)
                
                # Attack detection: SYN flood (lowered threshold for low traffic)
                if packet[TCP].flags == 2:
                    syn_count = sum(1 for f in flow['tcp_flags'] if f == 2)
                    if syn_count > 5 and flow['bwd_pkts'] == 0:  # Lowered from 10 to 5
                        flow['is_attack'] = True
                        
            elif UDP in packet:
                if flow['src_port'] == 0:
                    flow['src_port'] = packet[UDP].sport
                    flow['dst_port'] = packet[UDP].dport
                flow['protocol'] = 17
                
                # UDP flood detection (lowered threshold)
                total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']
                if total_pkts > 20:  # Lowered from 50 to 20
                    flow['is_attack'] = True
                    
            elif ICMP in packet:
                flow['protocol'] = 1
                
                # ICMP flood (lowered threshold for ping floods)
                if flow['fwd_pkts'] + flow['bwd_pkts'] > 10:  # Lowered from 30 to 10
                    flow['is_attack'] = True
    
    def save_current_window(self):
        """Save current flows to CSV and start new window"""
        if not self.flows:
            return
        
        self.window_count += 1
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_filename = self.output_dir / f"live_capture_{timestamp}_w{self.window_count}.csv"
        
        # Write CSV with CIC-DDoS2019 format
        with open(csv_filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol',
                'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
                'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
                'Flow Byts/s', 'Flow Pkts/s',
                'Fwd Pkts/s', 'Bwd Pkts/s',
                'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Max', 'Pkt Len Min',
                'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
                'ACK Flag Cnt', 'URG Flag Cnt',
                'Label'
            ])
            
            # Analyze for HTTP/HTTPS flood attacks (many connections from same source)
            src_ip_counts = {}
            server_ips = set()  # Track IPs acting as servers (source port 80/443)
            
            for (src, src_port, dst, dst_port, proto), flow in self.flows.items():
                # Track server IPs (responding from port 80/443)
                if proto == 6 and (src_port == 80 or src_port == 443 or src_port == 8080):
                    server_ips.add(src)
                
                # Count connections TO web ports (potential attacks)
                if proto == 6 and (dst_port == 80 or dst_port == 443 or dst_port == 8080):
                    src_ip_counts[src] = src_ip_counts.get(src, 0) + 1
            
            # Identify attacking IPs (many concurrent connections to web ports)
            # Exclude server IPs to avoid blocking the victim
            attacking_ips = set()
            for src_ip, count in src_ip_counts.items():
                if count >= 50 and src_ip not in server_ips:  # Don't mark servers as attackers
                    attacking_ips.add(src_ip)
            
            # Write flows
            for (src, src_port, dst, dst_port, proto), flow in self.flows.items():
                # Calculate duration
                duration = 0
                if flow['last_time'] and flow['first_time']:
                    duration = flow['last_time'] - flow['first_time']
                duration_us = int(duration * 1000000) if duration > 0 else 1
                
                # Calculate rates
                total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
                total_pkts = flow['fwd_pkts'] + flow['bwd_pkts']
                
                flow_byte_rate = total_bytes / duration if duration > 0 else 0
                flow_pkt_rate = total_pkts / duration if duration > 0 else 0
                fwd_pkt_rate = flow['fwd_pkts'] / duration if duration > 0 else 0
                bwd_pkt_rate = flow['bwd_pkts'] / duration if duration > 0 else 0
                
                # Packet length statistics
                pkt_len_mean = total_bytes / total_pkts if total_pkts > 0 else 0
                pkt_len_max = 1500
                pkt_len_min = 40
                pkt_len_std = 200
                
                # TCP flag counts
                syn_count = sum(1 for f in flow['tcp_flags'] if f & 0x02)
                ack_count = sum(1 for f in flow['tcp_flags'] if f & 0x10)
                fin_count = sum(1 for f in flow['tcp_flags'] if f & 0x01)
                rst_count = sum(1 for f in flow['tcp_flags'] if f & 0x04)
                psh_count = sum(1 for f in flow['tcp_flags'] if f & 0x08)
                urg_count = sum(1 for f in flow['tcp_flags'] if f & 0x20)
                
                # Determine label with heuristics (adjusted for low traffic)
                label = 'BENIGN'
                if flow['is_attack']:
                    label = 'Attack'
                elif src in attacking_ips:  # HTTP flood detection
                    label = 'Attack'
                elif flow_pkt_rate > 500:  # Lowered from 1000
                    label = 'Attack'
                elif total_pkts > 20 and flow['bwd_pkts'] == 0:  # Lowered from 100 to 20
                    label = 'Attack'
                elif syn_count > 10 and ack_count == 0:  # Lowered from 20 to 10
                    label = 'Syn'
                
                writer.writerow([
                    src, src_port, dst, dst_port, proto,
                    duration_us,
                    flow['fwd_pkts'], flow['bwd_pkts'],
                    flow['fwd_bytes'], flow['bwd_bytes'],
                    f"{flow_byte_rate:.2f}", f"{flow_pkt_rate:.2f}",
                    f"{fwd_pkt_rate:.2f}", f"{bwd_pkt_rate:.2f}",
                    f"{pkt_len_mean:.2f}", f"{pkt_len_std:.2f}",
                    pkt_len_max, pkt_len_min,
                    fin_count, syn_count, rst_count, psh_count,
                    ack_count, urg_count,
                    label
                ])
        
        flow_count = len(self.flows)
        # Count attack flows: either marked by heuristics OR from attacking IPs
        attack_count = sum(1 for (src, _, _, _, _), f in self.flows.items() 
                          if f['is_attack'] or src in attacking_ips)
        
        print(f"\n\033[92m[Window {self.window_count}]\033[0m {datetime.now().strftime('%H:%M:%S')}")
        print(f"  Saved: {csv_filename.name}")
        print(f"  Flows: {flow_count} | Packets: {self.total_packets}")
        
        # Show attacking IPs if detected
        if attacking_ips:
            print(f"  \033[91m⚠ HTTP FLOOD DETECTED from {len(attacking_ips)} IP(s)\033[0m")
            for ip in attacking_ips:
                conn_count = src_ip_counts.get(ip, 0)
                print(f"    {ip}: {conn_count} connections")
        
        print(f"  Attack flows: {attack_count}/{flow_count}", end='')
        
        if attack_count > flow_count * 0.5:
            print(f" \033[91m⚠ HIGH ATTACK TRAFFIC!\033[0m")
        else:
            print()
        
        # Update symlink to latest file
        latest_link = self.output_dir / "latest_capture.csv"
        try:
            if latest_link.exists() or latest_link.is_symlink():
                latest_link.unlink()
            latest_link.symlink_to(csv_filename.name)
        except OSError:
            # Fallback: copy file
            import shutil
            shutil.copy2(csv_filename, latest_link)
        
        # Clear flows for next window
        self.flows.clear()
        self.total_flows += flow_count
        self.window_start = time.time()
    
    def window_timer(self):
        """Timer thread that saves windows at regular intervals"""
        while self.is_running:
            time.sleep(1)  # Check every second
            
            elapsed = time.time() - self.window_start
            if elapsed >= self.window_duration:
                with self.lock:
                    if self.flows:  # Only save if we have flows
                        self.save_current_window()
    
    def start_capture(self):
        """Start packet capture with timed windows"""
        print("\033[92m" + "="*70)
        print("  Continuous Live Traffic Capture for DDoS Detection")
        print("="*70 + "\033[0m")
        print(f"\nConfiguration:")
        print(f"  Interface:       {self.interface}")
        print(f"  Window Duration: {self.window_duration} seconds")
        print(f"  Output Directory: {self.output_dir}")
        print(f"\n\033[93mCapturing traffic... (Press Ctrl+C to stop)\033[0m")
        print(f"\033[90mNew CSV file will be created every {self.window_duration} seconds\033[0m\n")
        
        # Register signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Start timer thread
        timer_thread = threading.Thread(target=self.window_timer, daemon=True)
        timer_thread.start()
        
        try:
            # Start sniffing with stop_filter to allow graceful exit
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                filter="ip",
                stop_filter=lambda x: not self.is_running  # Stop when is_running becomes False
            )
        except PermissionError:
            print("\n\033[91m[!] Error: Permission denied\033[0m")
            print("Run with: sudo python3 live_traffic_capture_continuous.py")
            sys.exit(1)
        except OSError as e:
            print(f"\n\033[91m[!] Error: {e}\033[0m")
            print(f"Interface '{self.interface}' not found")
            sys.exit(1)
        except KeyboardInterrupt:
            # This shouldn't happen since signal handler catches it, but just in case
            pass


def main():
    parser = argparse.ArgumentParser(
        description='Continuous live traffic capture for DDoS detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture on eth0, save every 10 seconds (default, recommended for DDoS)
  sudo python3 %(prog)s -i eth0 -o /mirror/ddos_mpi_detector/live_captures

  # Capture with 15-second windows (better IP diversity)
  sudo python3 %(prog)s -i eth0 -o ./captures -d 15

  # Capture with 5-second windows (faster detection)
  sudo python3 %(prog)s -i eth0 -o ./captures -d 5

  # Capture on wireless interface
  sudo python3 %(prog)s -i wlan0 -o ./captures
  
Window Duration Guidelines:
  5s   - Fast detection, fewer flows per window
  10s  - Balanced (default for DDoS multi-attacker scenarios)
  15s  - Best IP diversity, more flows, lower overhead
        """
    )
    
    parser.add_argument('-i', '--interface', 
                       default='eth0',
                       help='Network interface to capture (default: eth0)')
    
    parser.add_argument('-o', '--output', 
                       required=True,
                       help='Output directory for CSV files')
    
    parser.add_argument('-d', '--duration',
                       type=int,
                       default=10,
                       help='Window duration in seconds (default: 10, recommended for DDoS)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.duration < 1:
        print("Error: Window duration must be at least 1 second")
        sys.exit(1)
    
    # Create and start capture
    capture = ContinuousCapture(
        interface=args.interface,
        output_dir=args.output,
        window_duration=args.duration
    )
    
    capture.start_capture()


if __name__ == '__main__':
    main()
