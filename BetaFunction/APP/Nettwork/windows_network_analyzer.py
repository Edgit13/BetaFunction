#!/usr/bin/env python3
"""
Windows Network Analyzer
Windows-compatible network traffic analysis tool
"""

import os
import sys
import time
import subprocess
import platform
import socket
import re
from datetime import datetime
from collections import defaultdict
import threading
import queue

# Import Windows-compatible libraries
try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from colorama import init, Fore, Back, Style

    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


    # Define basic colors for compatibility
    class Fore:
        GREEN = YELLOW = RED = CYAN = MAGENTA = WHITE = BLUE = ''


    class Style:
        BRIGHT = RESET_ALL = ''


class WindowsNetworkUI:
    """Windows-style console UI"""

    @staticmethod
    def clear_screen():
        os.system('cls')

    @staticmethod
    def print_header(title):
        if COLORAMA_AVAILABLE:
            print(Fore.CYAN + "=" * 60)
            print(f"║{title:^58}║")
            print("=" * 60 + Style.RESET_ALL)
        else:
            print("=" * 60)
            print(f"{title:^60}")
            print("=" * 60)

    @staticmethod
    def print_menu():
        if COLORAMA_AVAILABLE:
            print(Fore.YELLOW + "\n[1] Real-time Traffic Monitor")
            print("[2] Active Connections & Ports")
            print("[3] Network Speed Test")
            print("[4] Network Information")
            print("[5] Ping Tools")
            print("[6] Trace Route")
            print("[7] Port Scanner")
            print("[8] Process Network Usage")
            print("[9] WiFi Information")
            print("[0] Exit")
            print(Fore.CYAN + "\nSelect option [0-9]: " + Style.RESET_ALL, end="")
        else:
            print("\n[1] Real-time Traffic Monitor")
            print("[2] Active Connections & Ports")
            print("[3] Network Speed Test")
            print("[4] Network Information")
            print("[5] Ping Tools")
            print("[6] Trace Route")
            print("[7] Port Scanner")
            print("[8] Process Network Usage")
            print("[9] WiFi Information")
            print("[0] Exit")
            print("\nSelect option [0-9]: ", end="")

    @staticmethod
    def print_error(msg):
        if COLORAMA_AVAILABLE:
            print(Fore.RED + f"[ERROR] {msg}")
        else:
            print(f"[ERROR] {msg}")

    @staticmethod
    def print_warning(msg):
        if COLORAMA_AVAILABLE:
            print(Fore.YELLOW + f"[WARNING] {msg}")
        else:
            print(f"[WARNING] {msg}")

    @staticmethod
    def print_success(msg):
        if COLORAMA_AVAILABLE:
            print(Fore.GREEN + f"[SUCCESS] {msg}")
        else:
            print(f"[SUCCESS] {msg}")

    @staticmethod
    def print_info(msg):
        if COLORAMA_AVAILABLE:
            print(Fore.CYAN + f"[INFO] {msg}")
        else:
            print(f"[INFO] {msg}")


class WindowsNetworkAnalyzer:
    """Windows Network Analysis Tool"""

    def __init__(self):
        self.ui = WindowsNetworkUI()
        self.monitoring = False
        self.system_info = self.get_system_info()

    def get_system_info(self):
        """Get Windows system information"""
        info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': socket.gethostname(),
        }
        try:
            info['ip_address'] = socket.gethostbyname(socket.gethostname())
        except:
            info['ip_address'] = 'Unknown'

        return info

    def check_admin_rights(self):
        """Check if running with Administrator rights"""
        try:
            # Try to create a file in Windows directory (requires admin)
            test_file = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'test.tmp')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            return True
        except:
            return False

    def real_time_traffic_monitor(self):
        """Monitor network traffic in real-time"""
        if not PSUTIL_AVAILABLE:
            self.ui.print_error("psutil library required! Install with: pip install psutil")
            return

        self.monitoring = True
        self.ui.clear_screen()
        self.ui.print_header("REAL-TIME NETWORK TRAFFIC MONITOR")
        print("Press Ctrl+C to stop\n")

        last_stats = {}

        try:
            while self.monitoring:
                current_stats = {}

                # Get network I/O counters
                net_io = psutil.net_io_counters(pernic=True)

                self.ui.clear_screen()
                self.ui.print_header(f"NETWORK TRAFFIC - {datetime.now().strftime('%H:%M:%S')}")

                print(f"{'Interface':<20} {'Received':>12} {'Sent':>12} {'Status':<12}")
                print("-" * 60)

                for interface, stats in net_io.items():
                    bytes_recv = stats.bytes_recv
                    bytes_sent = stats.bytes_sent

                    current_stats[interface] = (bytes_recv, bytes_sent)

                    # Calculate speed if we have previous stats
                    if interface in last_stats:
                        last_recv, last_sent = last_stats[interface]
                        time_diff = 2  # 2 seconds between updates

                        recv_speed = (bytes_recv - last_recv) / time_diff / 1024  # KB/s
                        sent_speed = (bytes_sent - last_sent) / time_diff / 1024  # KB/s

                        status = "🟢 ACTIVE" if recv_speed > 1 or sent_speed > 1 else "⚫ IDLE"

                        if COLORAMA_AVAILABLE:
                            if recv_speed > 100 or sent_speed > 100:
                                color = Fore.GREEN
                            elif recv_speed > 10 or sent_speed > 10:
                                color = Fore.YELLOW
                            else:
                                color = Fore.WHITE
                            print(
                                f"{color}{interface:<20} {recv_speed:>8.1f} KB/s {sent_speed:>8.1f} KB/s {status:<12}")
                        else:
                            print(f"{interface:<20} {recv_speed:>8.1f} KB/s {sent_speed:>8.1f} KB/s {status:<12}")
                    else:
                        print(f"{interface:<20} {'-':>8} KB/s {'-':>8} KB/s {'-':<12}")

                last_stats = current_stats

                # Show summary
                print("\n" + "=" * 60)
                total_recv = sum(stats.bytes_recv for stats in net_io.values())
                total_sent = sum(stats.bytes_sent for stats in net_io.values())

                print(
                    f"Total Received: {total_recv / 1024 / 1024:.2f} MB | Total Sent: {total_sent / 1024 / 1024:.2f} MB")

                time.sleep(2)

        except KeyboardInterrupt:
            self.monitoring = False
            self.ui.print_info("\nMonitoring stopped")

    def show_active_connections(self):
        """Show active network connections and ports"""
        self.ui.clear_screen()
        self.ui.print_header("ACTIVE CONNECTIONS & PORTS")

        try:
            # Use netstat command
            result = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True,
                text=True,
                shell=True
            )

            if result.returncode == 0:
                lines = result.stdout.split('\n')

                print(f"{'Protocol':<8} {'Local Address':<25} {'Foreign Address':<25} {'State':<12} {'PID':<8}")
                print("-" * 80)

                connection_count = 0
                for line in lines[3:]:  # Skip headers
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            proto = parts[0]
                            local = parts[1]
                            foreign = parts[2]
                            state = parts[3] if len(parts) > 3 else ''
                            pid = parts[4] if len(parts) > 4 else ''

                            # Try to get process name
                            process_name = ""
                            if pid and pid.isdigit():
                                try:
                                    process = psutil.Process(int(pid))
                                    process_name = process.name()
                                except:
                                    process_name = "Unknown"

                            if COLORAMA_AVAILABLE:
                                if 'ESTABLISHED' in state:
                                    color = Fore.GREEN
                                elif 'LISTENING' in state:
                                    color = Fore.YELLOW
                                else:
                                    color = Fore.WHITE
                                print(
                                    f"{color}{proto:<8} {local:<25} {foreign:<25} {state:<12} {pid:<8} {process_name}")
                            else:
                                print(f"{proto:<8} {local:<25} {foreign:<25} {state:<12} {pid:<8} {process_name}")

                            connection_count += 1
                            if connection_count >= 20:  # Limit display
                                print("\n... more connections available")
                                break

                print(f"\nTotal connections shown: {connection_count}")

                # Show listening ports
                print("\n" + "=" * 60)
                print("LISTENING PORTS:")
                print("-" * 60)

                listening_ports = []
                for line in lines:
                    if 'LISTENING' in line:
                        listening_ports.append(line.strip())

                for port in listening_ports[:10]:  # Show first 10
                    print(port)

                if len(listening_ports) > 10:
                    print(f"... and {len(listening_ports) - 10} more")

        except Exception as e:
            self.ui.print_error(f"Error getting connections: {e}")

    def network_speed_test(self):
        """Test network speed"""
        self.ui.clear_screen()
        self.ui.print_header("NETWORK SPEED TEST")

        print("Testing internet connection...\n")

        # Test 1: Ping test
        print("[1] PING TEST")
        print("-" * 40)

        test_servers = ['8.8.8.8', '1.1.1.1', 'google.com']

        for server in test_servers:
            try:
                print(f"\nPinging {server}...")
                result = subprocess.run(
                    ['ping', '-n', '4', server],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    # Parse ping results
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if 'Average' in line or 'avg' in line.lower():
                            print(f"  {line.strip()}")
                else:
                    print(f"  Failed to ping {server}")

            except subprocess.TimeoutExpired:
                print(f"  Timeout pinging {server}")
            except Exception as e:
                print(f"  Error: {e}")

        # Test 2: Download/Upload test (simplified)
        print("\n[2] BANDWIDTH TEST")
        print("-" * 40)

        try:
            import speedtest
            print("Running speed test (this may take a moment)...")

            st = speedtest.Speedtest()
            st.get_best_server()

            download_speed = st.download() / 1_000_000  # Convert to Mbps
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps

            print(f"\nDownload Speed: {download_speed:.2f} Mbps")
            print(f"Upload Speed: {upload_speed:.2f} Mbps")
            print(f"Ping: {st.results.ping:.0f} ms")

            # Quality assessment
            print("\n[3] CONNECTION QUALITY")
            print("-" * 40)

            if download_speed > 50:
                quality = "Excellent (Gaming/Streaming)"
            elif download_speed > 25:
                quality = "Good (HD Streaming)"
            elif download_speed > 10:
                quality = "Average (Web Browsing)"
            else:
                quality = "Poor (Basic browsing)"

            print(f"Quality: {quality}")

        except ImportError:
            print("Install speedtest-cli for full test: pip install speedtest-cli")
            print("\nRunning basic bandwidth estimation...")

            # Simple file download test
            try:
                import requests
                import time

                test_url = "http://ipv4.download.thinkbroadband.com/10MB.zip"
                start_time = time.time()

                response = requests.get(test_url, stream=True, timeout=5)
                total_size = 0

                for chunk in response.iter_content(chunk_size=8192):
                    total_size += len(chunk)
                    if time.time() - start_time > 3:  # Test for 3 seconds
                        break

                elapsed = time.time() - start_time
                if elapsed > 0:
                    speed_mbps = (total_size * 8) / elapsed / 1_000_000
                    print(f"Estimated Speed: {speed_mbps:.2f} Mbps")
                else:
                    print("Test too short for accurate measurement")

            except Exception as e:
                print(f"Basic test failed: {e}")

    def show_network_info(self):
        """Display comprehensive network information"""
        self.ui.clear_screen()
        self.ui.print_header("NETWORK INFORMATION")

        print(f"System: {self.system_info['system']} {self.system_info['release']}")
        print(f"Hostname: {self.system_info['hostname']}")
        print(f"IP Address: {self.system_info['ip_address']}")
        print()

        # Get detailed network info using ipconfig
        try:
            print("[1] IP CONFIGURATION")
            print("-" * 40)

            result = subprocess.run(
                ['ipconfig', '/all'],
                capture_output=True,
                text=True,
                shell=True
            )

            if result.returncode == 0:
                # Display key information
                lines = result.stdout.split('\n')
                for line in lines:
                    if any(keyword in line for keyword in ['IPv4', 'Physical', 'DHCP', 'DNS']):
                        print(line.strip())

            print("\n[2] ARP TABLE")
            print("-" * 40)

            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                shell=True
            )

            if result.returncode == 0:
                print(result.stdout[:500])  # Limit output

            print("\n[3] ROUTING TABLE")
            print("-" * 40)

            result = subprocess.run(
                ['route', 'print'],
                capture_output=True,
                text=True,
                shell=True
            )

            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[:30]:  # First 30 lines
                    print(line)

        except Exception as e:
            self.ui.print_error(f"Error getting network info: {e}")

    def ping_tools(self):
        """Various ping utilities"""
        self.ui.clear_screen()
        self.ui.print_header("PING TOOLS")

        print("[1] Ping Specific Host")
        print("[2] Continuous Ping")
        print("[3] Ping with Size")
        print("[4] Ping Statistics")
        print("[0] Back to Main Menu")
        print()

        choice = input("Select option [0-4]: ").strip()

        if choice == "1":
            host = input("Enter host to ping (IP or domain): ").strip()
            if host:
                subprocess.run(['ping', host])
        elif choice == "2":
            host = input("Enter host for continuous ping: ").strip()
            if host:
                subprocess.run(['ping', '-t', host])
        elif choice == "3":
            host = input("Enter host: ").strip()
            size = input("Packet size (bytes): ").strip()
            if host and size:
                subprocess.run(['ping', '-l', size, host])
        elif choice == "4":
            host = input("Enter host for statistics: ").strip()
            if host:
                subprocess.run(['ping', '-n', '10', host])

    def trace_route(self):
        """Trace route to destination"""
        self.ui.clear_screen()
        self.ui.print_header("TRACE ROUTE")

        host = input("Enter host to trace (IP or domain): ").strip()
        if host:
            try:
                subprocess.run(['tracert', host])
            except:
                self.ui.print_error("tracert command failed")

    def port_scanner(self):
        """Simple port scanner"""
        self.ui.clear_screen()
        self.ui.print_header("PORT SCANNER")

        host = input("Enter host to scan: ").strip() or '127.0.0.1'
        start_port = input("Start port (default 1): ").strip() or '1'
        end_port = input("End port (default 100): ").strip() or '100'

        try:
            start_port = int(start_port)
            end_port = int(end_port)

            print(f"\nScanning {host} ports {start_port}-{end_port}...")
            print("-" * 50)

            open_ports = []

            for port in range(start_port, min(end_port, start_port + 50) + 1):  # Limit to 50 ports
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((host, port))

                    if result == 0:
                        service = "Unknown"
                        try:
                            service = socket.getservbyport(port)
                        except:
                            pass

                        print(f"Port {port:5} [OPEN]  - {service}")
                        open_ports.append(port)
                    # else:
                    #     print(f"Port {port:5} [CLOSED]")

                    sock.close()

                except Exception as e:
                    pass

            print(f"\nFound {len(open_ports)} open ports")

        except ValueError:
            self.ui.print_error("Invalid port numbers")

    def process_network_usage(self):
        """Show network usage by process"""
        if not PSUTIL_AVAILABLE:
            self.ui.print_error("psutil required! Install: pip install psutil")
            return

        self.ui.clear_screen()
        self.ui.print_header("PROCESS NETWORK USAGE")

        try:
            # Get network connections by process
            connections = psutil.net_connections(kind='inet')

            process_connections = defaultdict(list)
            for conn in connections:
                if conn.pid:
                    process_connections[conn.pid].append(conn)

            print(f"{'PID':<8} {'Process Name':<25} {'Connections':<12} {'Status':<15}")
            print("-" * 60)

            for pid, conns in sorted(process_connections.items(), key=lambda x: len(x[1]), reverse=True)[:20]:
                try:
                    process = psutil.Process(pid)
                    name = process.name()
                    status = process.status()

                    # Get connection states
                    states = [conn.status for conn in conns if conn.status]
                    unique_states = set(states)

                    print(f"{pid:<8} {name:<25} {len(conns):<12} {', '.join(unique_states)[:15]}")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    print(f"{pid:<8} {'[Terminated]':<25} {len(conns):<12} {'N/A':<15}")

            print(f"\nTotal processes with network activity: {len(process_connections)}")

        except Exception as e:
            self.ui.print_error(f"Error getting process info: {e}")

    def wifi_information(self):
        """Show WiFi information (Windows specific)"""
        self.ui.clear_screen()
        self.ui.print_header("WI-FI INFORMATION")

        try:
            # Use netsh for WiFi info
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                shell=True
            )

            if result.returncode == 0:
                print(result.stdout)
            else:
                print("No WiFi interface found or command failed")

            print("\n" + "=" * 60)
            print("AVAILABLE WIFI NETWORKS:")
            print("-" * 60)

            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True,
                shell=True
            )

            if result.returncode == 0:
                print(result.stdout[:1000])  # Limit output
            else:
                print("Could not scan for networks")

        except Exception as e:
            self.ui.print_error(f"Error getting WiFi info: {e}")

    def main_loop(self):
        """Main program loop"""
        # Check for admin rights
        if not self.check_admin_rights():
            self.ui.print_warning("Running without Administrator rights")
            self.ui.print_warning("Some features may be limited")
            print()

        while True:
            self.ui.clear_screen()
            self.ui.print_header("WINDOWS NETWORK ANALYZER v1.0")

            print(f"System: {self.system_info['system']} {self.system_info['release']}")
            print(f"Hostname: {self.system_info['hostname']}")
            print(f"IP Address: {self.system_info['ip_address']}")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            self.ui.print_menu()

            choice = input().strip()

            if choice == '1':
                self.real_time_traffic_monitor()
            elif choice == '2':
                self.show_active_connections()
                input("\nPress Enter to continue...")
            elif choice == '3':
                self.network_speed_test()
                input("\nPress Enter to continue...")
            elif choice == '4':
                self.show_network_info()
                input("\nPress Enter to continue...")
            elif choice == '5':
                self.ping_tools()
            elif choice == '6':
                self.trace_route()
                input("\nPress Enter to continue...")
            elif choice == '7':
                self.port_scanner()
                input("\nPress Enter to continue...")
            elif choice == '8':
                self.process_network_usage()
                input("\nPress Enter to continue...")
            elif choice == '9':
                self.wifi_information()
                input("\nPress Enter to continue...")
            elif choice == '0':
                self.ui.clear_screen()
                self.ui.print_header("EXIT")
                print("\nThank you for using Windows Network Analyzer!")
                print("Goodbye!")
                time.sleep(2)
                break
            else:
                self.ui.print_error("Invalid choice!")
                time.sleep(1)


def main():
    """Main function"""
    analyzer = WindowsNetworkAnalyzer()
    analyzer.main_loop()


if __name__ == "__main__":
    main()