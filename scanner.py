import socket
import ssl
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import queue

# Color class for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

# Thread-safe queue to collect results from worker threads
results_queue = queue.Queue()
# Lock to prevent multiple threads printing simultaneously
print_lock = threading.Lock()

class VulnerabilityScanner:
    def __init__(self, targets, ports):
        self.targets = targets
        self.ports = ports
        self.https_ports = {443, 8443, 4443} 
        self.scan_start_time = datetime.now()
        self.output_filename = f"scan_results_{self.scan_start_time.strftime('%Y%m%d_%H%M%S')}.txt"
        self.log_to_file("="*60 + "\n")
        self.log_to_file(f"Scan started at: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_to_file(f"Targets: {', '.join(self.targets)}\n")
        self.log_to_file(f"Ports: {', '.join(map(str, self.ports))}\n")
        self.log_to_file("="*60 + "\n\n")

    def log_to_file(self, message):
        """Writes a message to the log file."""
        with open(self.output_filename, "a", encoding="utf-8") as f:
            f.write(message)

    def scan_port(self, ip, port):
        """Scans a single port on a given IP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                if sock.connect_ex((ip, port)) == 0:
                    message = f"{Colors.GREEN} {ip}:{port} - OPEN{Colors.RESET}"
                    results_queue.put(message)
                    
                    # Try to get banner, check for HTTP
                    self.probe_service(ip, port)
        except Exception:
            # Ignore other errors
            pass

    def probe_service(self, ip, port):
        """Probes the service for more details."""
        is_https = port in self.https_ports
        
        try:
            # Create base socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            
            # If HTTPS, wrap the socket with SSL
            if is_https:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                secure_sock = context.wrap_socket(sock, server_hostname=ip)
                secure_sock.connect((ip, port))
                conn = secure_sock
            else:
                sock.connect((ip, port))
                conn = sock
            
            # Send HTTP HEAD request
            request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
            conn.sendall(request.encode('utf-8'))
            response_bytes = conn.recv(4096)
            
            try:
                # Try decoding as UTF-8
                response = response_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # If it fails, it might be binary data (e.g., SSH banner)
                response = response_bytes.decode('latin-1', errors='ignore')

            if response.startswith("HTTP/"):
                self.analyze_http_response(response)
            else:
                # If not HTTP, it might be a banner from another service
                banner_info = f"    {Colors.BLUE}[i] Banner/Non-HTTP Service: {response.strip()}{Colors.RESET}"
                results_queue.put(banner_info)

        except ssl.SSLError as e:
            ssl_error = f"    {Colors.YELLOW}[!] SSL Error on port {port}: {e}{Colors.RESET}"
            results_queue.put(ssl_error)
        except Exception as e:
            error_msg = f"    {Colors.YELLOW}[!] Could not grab banner from port {port}: Possibly not a text-based service.{Colors.RESET}"
            results_queue.put(error_msg)
        finally:
            if 'conn' in locals():
                conn.close()

    def analyze_http_response(self, response):
        """Analyzes an HTTP response and queues the findings."""
        lines = response.splitlines()
        first_line = lines[0]
        status_code = first_line.split(' ')[1]
        
        status_msg = f"    {Colors.YELLOW}[+] HTTP service detected with status code: {status_code}{Colors.RESET}"
        results_queue.put(status_msg)
        
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        
        # Analyze for "vulnerability" signatures
        if status_code == "403":
            results_queue.put(f"        {Colors.RED}[!] Found 403 Forbidden. May indicate hidden resources or misconfiguration.{Colors.RESET}")
        elif status_code == "500":
            results_queue.put(f"        {Colors.RED}[!] Found 500 Internal Server Error. Sign of a failing application.{Colors.RESET}")
        
        findings = {
            'server': 'Server Version Information Leak',
            'x-powered-by': 'Platform/Language Information Leak',
            'x-aspnet-version': 'ASP.NET Version Information Leak'
        }
        for key, desc in findings.items():
            if key in headers:
                results_queue.put(f"        {Colors.RED}[!] {desc}: {headers[key]}{Colors.RESET}")

    def run(self):
        """Executes the scan."""
        with ThreadPoolExecutor(max_workers=100) as executor:
            tasks = {executor.submit(self.scan_port, ip, port) 
                     for ip in self.targets for port in self.ports}
        
        print(f"[*] Created {len(tasks)} scanning tasks. Results will be displayed below and saved to '{self.output_filename}'...")

def print_results():
    """Retrieves results from the queue and prints them."""
    while True:
        try:
            message = results_queue.get(timeout=5)
            with print_lock:
                # Remove color codes before writing to file
                with open(scanner.output_filename, "a", encoding="utf-8") as f:
                    ansi_escape = __import__('re').compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    f.write(ansi_escape.sub('', message) + "\n")
                print(message)
            results_queue.task_done()
        except queue.Empty:
            # If the queue is empty for 5 seconds, assume scanning is done
            break

def parse_ports(port_str):
    ports = set()
    parts = port_str.split(',')
    for part in parts:
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if start <= end:
                    ports.update(range(start, end + 1))
            except ValueError:
                print(f"{Colors.RED}[!] Invalid port range: {part}{Colors.RESET}")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                print(f"{Colors.RED}[!] Invalid port: {part}{Colors.RESET}")
    return sorted(list(ports))

def main():
    print("="*60)
    print("VULNERABILITY SCANNER")
    print("="*60)

    target_str = input("Enter target IP(s) or hostname(s) (comma-separated): ")
    try:
        targets = [socket.gethostbyname(ip.strip()) for ip in target_str.split(',')]
    except socket.gaierror as e:
        print(f"{Colors.RED}[!] Error resolving hostname: {e}. Please check your targets.{Colors.RESET}")
        sys.exit(1)

    port_str = input("Enter port(s) or port range(s) (e.g., 80,443,8000-8080): ")
    ports_to_scan = parse_ports(port_str)

    if not targets or not ports_to_scan:
        print(f"{Colors.RED}No valid targets or ports to scan. Exiting...{Colors.RESET}")
        sys.exit(1)
        
    global scanner
    scanner = VulnerabilityScanner(targets, ports_to_scan)
    
    printer_thread = threading.Thread(target=print_results, daemon=True)
    printer_thread.start()
    
    scanner.run()
    
    results_queue.join()
    print("\n" + "="*60)
    print(f"{Colors.GREEN}Scan complete!{Colors.RESET}")
    print(f"Full results have been saved to: {Colors.YELLOW}{scanner.output_filename}{Colors.RESET}")
    print("="*60)

if __name__ == "__main__":
    main()