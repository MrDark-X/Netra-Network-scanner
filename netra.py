import sys
import socket
import ssl
import select
import pyfiglet
import platform
import subprocess
import os
import requests
from ipaddress import IPv4Interface
from scapy.all import ARP, Ether, srp


# Check for missing modules and install them if necessary
REQUIRED_MODULES = ['scapy', 'ipaddress', 'requests', 'pyfiglet', 'socket', 'select', 'sys', 'ssl', 'os', 'platform', 'subprocess']
MISSING_MODULES = []

for module in REQUIRED_MODULES:
    try:
        __import__(module)
    except ImportError:
        MISSING_MODULES.append(module)

if MISSING_MODULES:

    print(f"The following modules are missing: {', '.join(MISSING_MODULES)}")
    print("Installing missing modules...")

    for module in MISSING_MODULES:
        subprocess.check_call([sys.executable, "-m", "pip3", "install", module])


# Validate user choice
def validate_choice(choice, valid_choices):
    while choice not in valid_choices:
        print("Invalid choice. Please try again.")
        choice = input("Enter your choice: ")
    return choice

# Validate scan type
def validate_scan_type(scan_type):
    valid_scan_types = ['1', '2', '3', '4', '5']
    while scan_type not in valid_scan_types:
        print("Invalid scan type. Please try again.")
        scan_type = input("Enter your choice: ")
    return scan_type

# Validate scan option
def validate_scan_option(scan_option):
    valid_scan_options = ['1', '2']
    while scan_option not in valid_scan_options:
        print("Invalid scan option. Please try again.")
        scan_option = input("Enter your choice: ")
    return scan_option


# Function to scan open ports
def scan_open_ports(target, scan_all_ports, scan_type='TCP Connect', progress_callback=None):
    print(f"Scanning {target} for open ports...")
    total_ports = 65535 if scan_all_ports else 1000
    open_ports = []

    try:
        if scan_all_ports:
            start_port = 1
            end_port = 65536
        else:
            start_port = 1
            end_port = 1024
        
        # Function to check if a key is pressed
        def is_key_pressed():
            if os.name == 'nt':  # Windows
                import msvcrt
                return msvcrt.kbhit() and msvcrt.getch() == b'\r'
            else:   # Linux
                return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])  # type: ignore



        for port in range(start_port, end_port):
            if is_key_pressed():
                print(f"\rScanning port {port} - Progress: {scan_progress:.2f}%", end="", flush=True)


            if scan_type == 'TCP Connect':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()

            elif scan_type == 'UDP Scan':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()

            elif scan_type == 'Aggressive Scan':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()

            elif scan_type == 'IDEAL Scan':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()

            elif scan_type == 'NULL Scan':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()

            # Calculate and update scan progress
            scan_progress = (port / total_ports) * 100.0

    except KeyboardInterrupt:
        print("Scan interrupted by the user.")

    return open_ports


# Function to perform service/version detection
def perform_service_detection(target, open_ports):
    print(f"Performing service/version detection on {target}...")

    try:
        for port in open_ports:
            # Check if the port is a common well-known port (0-1023)
            if port <= 1023:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except OSError:
                        service = "Unknown"
                    print(f"Port {port}: {service}")

                # Perform version detection for specific services (Add more cases as needed)
                if port == 80:  # HTTP
                    http_version = get_http_version(target, port)
                    if http_version:
                        print(f"  - HTTP Version: {http_version}")
                elif port == 443:  # HTTPS
                    https_version = get_https_version(target, port)
                    if https_version:
                        print(f"  - HTTPS Version: {https_version}")
                elif port == 21:  # FTP
                    ftp_banner = get_ftp_banner(target, port)
                    if ftp_banner:
                        print(f"  - FTP Banner: {ftp_banner}")
                elif port == 22:  # SSH
                    ssh_banner = get_ssh_banner(target, port)
                    if ssh_banner:
                        print(f"  - SSH Banner: {ssh_banner}")
                elif port == 23:  # Telnet
                    telnet_banner = get_telnet_version(target, port)
                    if telnet_banner:
                        print(f"  - Telnet Banner: {telnet_banner}")
                elif port == 25:  # SMTP
                    smtp_banner = get_smtp_version(target, port)
                    if smtp_banner:
                        print(f"  - SMTP Banner: {smtp_banner}")
                elif port == 123:  # NTP
                    ntp_banner = get_ntp_version(target, port)
                    if ntp_banner:
                        print(f"  - NTP Banner: {ntp_banner}")
                elif port == 179: # BGP
                    bgp_banner = get_bgp_version(target, port)
                    if bgp_banner:
                        print(f"  - BGP Banner: {bgp_banner}")
                elif port == 500:  # ISAKMP (IKE)
                    ike_version = get_ike_version(target, port)
                    if ike_version:
                        print(f"  - IKE Version: {ike_version}")
                elif port == 587:  # SMTP (Submission)
                    smtp_version = get_smtp_version(target, port)
                    if smtp_version:
                        print(f"  - SMTP Version: {smtp_version}")
                elif port == 53:  # DNS
                    dns_version = get_dns_version(target, port)
                    if dns_version:
                        print(f"  - DNS Version: {dns_version}")
                elif port == 445:  # SMB (NetBIOS)
                    smb_version = get_smb_version(target, port)
                    if smb_version:
                        print(f"  - SMB Version: {smb_version}")
                elif port == 110:  # POP3
                    pop3_version = get_pop3_version(target, port)
                    if pop3_version:
                        print(f"  - POP3 Version: {pop3_version}")
                elif port == 67:  # DHCP
                    dhcp_version = get_dhcp_version(target, port)
                    if dhcp_version:
                        print(f"  - DHCP Version: {dhcp_version}")
                elif port == 161:  # SNMP
                    snmp_version = get_snmp_version(target, port)
                    if snmp_version:
                        print(f"  - SNMP Version: {snmp_version}")
                elif port == 137:  # NetBIOS Name Service
                    netbios_version = get_netbios_version(target, port)
                    if netbios_version:
                        print(f"  - NetBIOS Version: {netbios_version}")
                elif port == 389:  # LDAP
                    ldap_version = get_ldap_version(target, port)
                    if ldap_version:
                        print(f"  - LDAP Version: {ldap_version}")
                elif port == 636:  # LDAPS
                    ldaps_version = get_ldaps_version(target, port)
                    if ldaps_version:
                        print(f"  - LDAPS Version: {ldaps_version}")
                elif port == 143:  # IMAP
                    imap_version = get_imap_version(target, port)
                    if imap_version:
                        print(f"  - IMAP Version: {imap_version}")
                    # Add more cases for other well-known ports
                    sock.close()

    except KeyboardInterrupt:
        print("Service detection interrupted by the user.")


# Function to get the HTTP version
def get_http_version(target, port):
    try:
        request = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.send(request.encode())
        response = sock.recv(4096)
        http_version = response.decode().split('\r\n')[0].split(' ')[0]
        sock.close()
        return http_version

    except Exception as e:
        print(f"Error occurred during HTTP version detection: {e}")
        return None


# Function to get the HTTPS version
def get_https_version(target, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as sslsock:
                https_version = sslsock.version()
                return https_version

    except Exception as e:
        print(f"Error occurred during HTTPS version detection: {e}")
        return None


# Function to get the FTP banner
def get_ftp_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        response = sock.recv(4096)
        ftp_banner = response.decode().strip()
        sock.close()
        return ftp_banner

    except Exception as e:
        print(f"Error occurred during FTP banner grabbing: {e}")
        return None


# Function to get the SSH banner
def get_ssh_banner(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        response = sock.recv(4096)
        ssh_banner = response.decode().strip()
        sock.close()
        return ssh_banner

    except Exception as e:
        print(f"Error occurred during SSH banner grabbing: {e}")
        return None


# Function to get Telnet version
def get_telnet_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.sendall(b"\xff\xfd\x18\xff\xfd\x1f\xff\xfd\x20\r\n")
        response = sock.recv(1024)
        sock.close()

        if b"Telnet" in response:
            version = response.split(b"Telnet")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get SMTP version
def get_smtp_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        response = sock.recv(1024)
        sock.sendall(b"EHLO example.com\r\n")
        response += sock.recv(1024)
        sock.close()

        if b"SMTP" in response:
            version = response.split(b"SMTP")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None

# Function to get NTP (Network Time Protocol) version
def get_ntp_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'\x1b' + 47 * b'\0', (target, port))
        response, _ = sock.recvfrom(1024)
        sock.close()

        if response:
            version = response.split(b' ')[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get BGP (Border Gateway Protocol) version
def get_bgp_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.sendall(b'\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff')
        response = sock.recv(1024)
        sock.close()

        if response:
            version = response.split(b'BGP')[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get IKE (Internet Key Exchange) version
def get_ike_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b'\x00\x00\x00\x00\x00\x02\x00\x00\x00\x02', (target, port))
        response, _ = sock.recvfrom(1024)
        sock.close()

        if response:
            version = response.split(b'IKE')[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get SMTP (Simple Mail Transfer Protocol) version
def get_smtp_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        response = sock.recv(1024)
        sock.sendall(b"EHLO example.com\r\n")
        response += sock.recv(1024)
        sock.close()

        if b"SMTP" in response:
            version = response.split(b"SMTP")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get DNS (Domain Name System) version
def get_dns_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.sendall(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01")
        response = sock.recv(1024)
        sock.close()

        if b"DNS" in response:
            version = response.split(b"DNS")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get SMB (Server Message Block) version
def get_smb_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.sendall(b"\x00\x00\x00\x90\xfe\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x26\x31\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        response = sock.recv(1024)
        sock.close()

        if b"SMB" in response:
            version = response.split(b"SMB")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get POP3 (Post Office Protocol) version
def get_pop3_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        response = sock.recv(1024)
        sock.sendall(b"VERSION\r\n")
        response += sock.recv(1024)
        sock.close()

        if b"+OK" in response:
            version = response.split(b"+OK")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get DHCP (Dynamic Host Configuration Protocol) version
def get_dhcp_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b"\x01\x01\x06\x00\x07\x23\x00\x01\x16\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", (target, port))
        response, _ = sock.recvfrom(1024)
        sock.close()

        if b"DHCP" in response:
            version = response.split(b"DHCP")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get LDAP (Lightweight Directory Access Protocol) version
def get_ldap_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.sendall(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80")
        response = sock.recv(1024)
        sock.close()

        if b"LDAP" in response:
            version = response.split(b"LDAP")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get LDAPS (LDAP over SSL/TLS) version
def get_ldaps_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        ssl_sock = ssl.wrap_socket(sock)
        ssl_sock.sendall(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80")
        response = ssl_sock.recv(1024)
        ssl_sock.close()

        if b"LDAPS" in response:
            version = response.split(b"LDAPS")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get IMAP (Internet Message Access Protocol) version
def get_imap_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        response = sock.recv(1024)
        sock.sendall(b"A001 CAPABILITY\r\n")
        response += sock.recv(1024)
        sock.close()

        if b"* CAPABILITY" in response:
            version = response.split(b"* CAPABILITY")[1].strip()
            return version.decode()

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get SNMP (Simple Network Management Protocol) version
def get_snmp_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x71\x25\xd9\xab\x02\x01\x00\x02\x01\x7f\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", (target, port))
        response, _ = sock.recvfrom(1024)
        sock.close()

        if response[0] == 0x30:
            version = response[22]
            return str(version)

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None


# Function to get NetBIOS version
def get_netbios_version(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        sock.sendall(b"\x82\x01\x2b\x00\x00\x00\x00")
        response = sock.recv(1024)
        sock.close()

        if len(response) >= 8:
            version = response[7]
            return str(version)

    except (socket.timeout, ConnectionRefusedError):
        pass

    return None



# Function to retrive Mac Vendor name
def retrieve_vendor(mac_address):
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown"
    except requests.exceptions.RequestException:
        return "Error"



def get_network_interface():
    # Execute the 'ip' command to retrieve the network interface name
    process = subprocess.Popen(['ip', 'route'], stdout=subprocess.PIPE)
    output, _ = process.communicate()
    output = output.decode()

    # Parse the output to extract the network interface name
    interface = output.split('\n')[0].split()[4]

    return interface



# Function to discover all hosts in the network
def discover_hosts():
    print("Discovering all hosts in the network...")
    try:
        ip_addresses = socket.gethostbyname_ex(socket.gethostname())[2]
        hosts = []

        for ip_address in ip_addresses:
            interface = IPv4Interface(ip_address)
            network_id = interface.network.network_address

            # Print the IP address considered for network discovery
            print(f"Considering IP address: {ip_address}")

            # Create an ARP request packet
            arp = ARP(pdst=f"{ip_address}/24")
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Send the packet and receive responses
            if platform.system() == "Windows":
                result = srp(packet, timeout=3, verbose=0)[0]
            else:  # Linux
                interface_name = get_network_interface()
                result = srp(packet, timeout=3, verbose=0, iface=interface_name)[0]


            # Extract the IP and MAC addresses from the responses
            for sent, received in result:
                mac_address = received.hwsrc
                vendor = retrieve_vendor(mac_address)
                hosts.append({'ip': received.psrc, 'mac': mac_address, 'vendor': vendor})

        # Print the network ID
        if network_id:
            print(f"\nNetwork ID: {network_id}\n")

        # Print the discovered hosts
        if hosts:
            print("Discovered hosts in the network:")
            for host in hosts:
                print(f"IP: {host['ip']}, MAC: {host['mac']}, Vendor: {host['vendor']}")
        else:
            print("No hosts found in the network.")

    except Exception as e:
        print(f"An error occurred while discovering hosts: {e}")
        sys.exit(1)



# Main function
def main():
    result = pyfiglet.figlet_format("NETRA")
    print(result)
    print("-------------------------------------------------------------------------------")
    print("Welcome to NETRA - A Network Scanning Tool by Chalamalasetty Yaswanth Surya")
    print("-------------------------------------------------------------------------------")
    print("This script allows you to scan for open ports on a target system or discover all hosts in the network.\n")

    while True:
        print("Please select an option:")
        print("1. Discover all hosts in the network")
        print("2. Scan for open ports on a specific target")
        choice = input("Enter your choice (1/2): ")
        choice = validate_choice(choice, ['1', '2'])

        if choice == '1':
            discover_hosts()
            break
        elif choice == '2':
            target = input("Enter the IP address to scan for open ports: ")
            scan_type = input(
                "Select scan type:\n1. TCP Connect Scan\n2. UDP Scan\n3. Aggressive Scan\n4. IDEAL Scan\n5. NULL Scan\nEnter your choice (1/2/3/4/5): ")
            scan_type = validate_scan_type(scan_type)

            if scan_type == '1':
                scan_type = 'TCP Connect'
            elif scan_type == '2':
                scan_type = 'UDP Scan'
            elif scan_type == '3':
                scan_type = 'Aggressive Scan'
            elif scan_type == '4':
                scan_type = 'IDEAL Scan'
            elif scan_type == '5':
                scan_type = 'NULL Scan'
            else:
                print("Invalid choice. Defaulting to TCP Connect Scan.")
                scan_type = 'TCP Connect'

            scan_option = input(
                "Select port scanning option:\n1. Standard ports (1000 ports)\n2. All ports\nEnter your choice (1/2): ")
            scan_option = validate_scan_option(scan_option)
            if scan_option == '1':
                scan_all_ports = False
            elif scan_option == '2':
                scan_all_ports = True
            else:
                print("Invalid choice. Defaulting to standard ports.")
                scan_all_ports = False



            open_ports = scan_open_ports(target, scan_all_ports, scan_type)
            if open_ports:
                print(f"\nOpen ports on {target}:")
                for port in open_ports:
                    print(f"Port {port}: Open")

                detect_services = input("Perform service/version detection? (Y/N): ")
                if detect_services.upper() == 'Y':
                    perform_service_detection(target, open_ports)
            else:
                print(f"\nNo open ports found on {target}.")

            print("\nThank you for using NETRA tool.")
            sys.exit()
        else:
            print("Invalid choice. Please try again.\n")


if __name__ == '__main__':
    main()
