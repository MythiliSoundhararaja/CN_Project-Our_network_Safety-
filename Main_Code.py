# Function for network reconnaissance
def network_reconnaissance(target_ip):
    print("Starting Network Safety Check - Network Reconnaissance...")
    
    # Get the hostname from the IP address
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
        print(f"Hostname for IP {target_ip}: {hostname}")
    except socket.herror:
        print("Hostname could not be found.")
    
    # Port scanning using Nmap
    scanner = nmap.PortScanner()
    try:
        scanner.scan(target_ip, '1-1024')  # Scan commonly used ports
        print("\nPort Scan Results:")
        for port in scanner[target_ip]['tcp']:
            state = scanner[target_ip]['tcp'][port]['state']
            print(f"Port {port}: {state}")
    except Exception as e:
        print(f"Error during scanning: {e}")

# Function for vulnerability scanning
def vulnerability_scanning(target_ip):
    print(f"\nStarting Network Safety Check - Vulnerability Scanning on {target_ip}...")
    # Simulate vulnerability scanning by checking for common issues
    common_vulnerabilities = {
        "FTP": "Open and insecure FTP service",
        "SSH": "Outdated SSH version",
        "HTTP": "Open HTTP port with no HTTPS",
        "Telnet": "Unencrypted Telnet service"
    }
    # Convert dictionary items to a list to sample
    found_vulnerabilities = random.sample(list(common_vulnerabilities.items()), 2)
    if found_vulnerabilities:
        print("Vulnerability Scan Results:")
        for port, issue in found_vulnerabilities:
            print(f"Port {port}: {issue}")
    else:
        print("No critical vulnerabilities detected.")

# Function for penetration testing
def penetration_testing(target_ip):
    print(f"\nStarting Network Safety Check - Penetration Testing on {target_ip}...")
    # Simulate penetration testing by trying basic exploits (for demonstration only)
    simulated_exploits = ["SQL Injection", "Weak Password Guess", "Cross-Site Scripting (XSS)"]
    successful_exploits = random.sample(simulated_exploits, 1)  # Randomly select an exploit
    if successful_exploits:
        print("Penetration Testing Results:")
        for exploit in successful_exploits:
            print(f"Exploit Attempted: {exploit} - Success")
    else:
        print("No successful penetration detected.")

# Function for generating a safety report
def generate_report(target_ip):
    print(f"\nGenerating Network Safety Report for {target_ip}...")
    # Placeholder report content with basic safety evaluation
    report_content = f"""
    Network Safety Report for {target_ip}
    ====================================
    1. Reconnaissance Completed: Ports scanned and host identified.
    2. Vulnerabilities Found: Yes (see results)
    3. Penetration Testing Results: Exploit attempts recorded.
    
    Recommendation:
    - Close or secure any open and unprotected ports.
    - Update any outdated software versions and disable unsecured protocols.
    - Implement strong passwords and utilize HTTPS instead of HTTP.
    """
    print(report_content)

# Main function to execute the network safety assessment
def main():
    target_ip = '127.0.0.1'  # Loopback IP for testing on your local machine
    network_reconnaissance(target_ip)
    vulnerability_scanning(target_ip)
    penetration_testing(target_ip)
    generate_report(target_ip)

if __name__ == "__main__":
    main()
