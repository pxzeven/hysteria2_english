# hysteria2  一键安装脚本
import glob
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from urllib import parse

import requests


def agree_treaty():       # Function: User agreement
    def hy_shortcut():   # Add hy2 shortcut
        hy2_shortcut = Path(r"/usr/local/bin/hy2")  # Create shortcut
        hy2_shortcut.write_text("#!/bin/bash\nwget -O hy2.py https://raw.githubusercontent.com/pxzeven/hysteria2_english/main/hysteria2.py && chmod +x hy2.py && python3 hy2.py\n")  # Write content
        hy2_shortcut.chmod(0o755)
    file_agree = Path(r"/etc/hy2config/agree.txt")  # Extract filename
    if file_agree.exists():       # Check if file exists, if yes, skip
        print("You have already agreed, thank you.")
        hy_shortcut()
    else:
        while True:
            print("I agree that using this program must comply with the laws and regulations of the server location, the country where it is located, and the user's country. The program author is not responsible for any improper conduct by the user. This program is for learning and exchange purposes only and must not be used for any commercial purposes.")
            choose_1 = input("Do you agree and have read the hysteria2 installation terms above [y/n]: ")
            if choose_1 == "y":
                check_file = subprocess.run("mkdir /etc/hy2config && touch /etc/hy2config/agree.txt && touch /etc/hy2config/hy2_url_scheme.txt",shell = True)
                print(check_file)    # Create file when user agrees, skip next time
                hy_shortcut()
                break
            elif choose_1 == "n":
                print("Please agree to the terms to install.")
                sys.exit()
            else:
                print("\033[91mPlease enter a valid option!\033[m")

def hysteria2_install():    # Install hysteria2
    while True:
        choice_1 = input("Install/Update hysteria2 [y/n]: ")
        if choice_1 == "y":
            print("1. Install latest version by default\n2. Install specific version")
            choice_2 = input("Enter option: ")
            if choice_2 == "1":
                hy2_install = subprocess.run("bash <(curl -fsSL https://get.hy2.sh/)",shell = True,executable="/bin/bash")  # Call official script
                print(hy2_install)
                print("--------------")
                print("\033[91mhysteria2 installation complete, please proceed to one-key configuration\033[m")
                print("--------------")
                hysteria2_config()
                break
            elif choice_2 == "2":
                version_1 = input("Enter the version number you want to install (e.g., 2.6.0): ")
                hy2_install_2 = subprocess.run(f"bash <(curl -fsSL https://get.hy2.sh/) --version v{version_1}",shell=True,executable="/bin/bash")  # Install specific version
                print(hy2_install_2)
                print("--------------")
                print(f"\033[91mhysteria2 version {version_1} installed, please proceed to one-key configuration!!!\033[m")
                print("--------------")
                hysteria2_config()
                break
            else:
                print("\033[91mInput error, please re-enter\033[m")
        elif choice_1 == "n":
            print("Cancelled hysteria2 installation")
            break
        else:
            print("\033[91mInput error, please re-enter\033[m")

def hysteria2_uninstall():   # Uninstall hysteria2
    while True:
        choice_1 = input("Uninstall hysteria2 [y/n]: ")
        if choice_1 == "y":
            hy2_uninstall_1 = subprocess.run("bash <(curl -fsSL https://get.hy2.sh/) --remove",shell = True,executable="/bin/bash")   # Call official script to uninstall
            print(hy2_uninstall_1)
            # Stop and disable iptables restore service
            subprocess.run(["systemctl", "stop", "hysteria-iptables.service"], stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "disable", "hysteria-iptables.service"], stderr=subprocess.DEVNULL)
            # Clean iptables rules
            subprocess.run(["/bin/bash", "/etc/hy2config/jump_port_back.sh"], stderr=subprocess.DEVNULL)
            # Delete all config files and services
            
            # Use glob to handle wildcard
            wildcard_paths = glob.glob("/etc/systemd/system/multi-user.target.wants/hysteria-server@*.service")
            for path in wildcard_paths:
                try:
                    Path(path).unlink(missing_ok=True)
                except Exception:
                    pass
            
            # Delete other paths
            paths_to_remove = [
                "/etc/hysteria",
                "/etc/systemd/system/multi-user.target.wants/hysteria-server.service",
                "/etc/systemd/system/hysteria-iptables.service",
                "/etc/hy2config/iptables-rules.v4",
                "/etc/hy2config/iptables-rules.v6",
                "/etc/ssl/private/",
                "/etc/hy2config",
                "/usr/local/bin/hy2"
            ]
            for path_str in paths_to_remove:
                try:
                    path = Path(path_str)
                    if path.is_file():
                        path.unlink(missing_ok=True)
                    elif path.is_dir():
                        shutil.rmtree(path, ignore_errors=True)
                except Exception:
                    pass
            
            subprocess.run(["systemctl", "daemon-reload"])
            print("Uninstall hysterical 2 complete")
            sys.exit()
        elif choice_1 == "n":
            print("Cancelled uninstall hysteria2")
            break
        else:
            print("\033[91mInput error, please re-enter\033[m")

def server_manage():   # hysteria2 service management
    while True:
            print("1. Start service (Enable auto-start)\n2. Stop service\n3. Restart service\n4. View service status\n5. View logs\n6. View hy2 version info\n0. Back")
            choice_2 = input("Enter option: ")
            if choice_2 == "1":
                print(subprocess.run("systemctl enable --now hysteria-server.service",shell=True))
            elif choice_2 == "2":
                print(subprocess.run("systemctl stop hysteria-server.service",shell=True))
            elif choice_2 == "3":
                print(subprocess.run("systemctl restart hysteria-server.service",shell=True))
            elif choice_2 == "4":
                print("\033[91mEnter q to exit view\033[m")
                print(subprocess.run("systemctl status hysteria-server.service",shell=True))
            elif choice_2 == "5":
                print(subprocess.run("journalctl --no-pager -e -u hysteria-server.service",shell=True))
            elif choice_2 == "6":
                os.system("/usr/local/bin/hysteria version")
            elif choice_2 == "0":
                break
            else:
                print("\033[91mInput error, please re-enter\033[m")

def create_iptables_persistence_service():
    """Create systemd service to restore iptables rules on boot"""
    # Create restore script, including error handling
    restore_script_content = """#!/bin/bash
# Hysteria2 iptables rules restoration script

set -e  # Exit on error

# Verify and restore IPv4 rules
if [ -f /etc/hy2config/iptables-rules.v4 ]; then
    if [ -s /etc/hy2config/iptables-rules.v4 ]; then
        if iptables-restore -t < /etc/hy2config/iptables-rules.v4 2>/dev/null; then
            iptables-restore < /etc/hy2config/iptables-rules.v4
            echo "IPv4 iptables rules restored successfully" | logger -t hysteria2-iptables
        else
            echo "IPv4 iptables rules file invalid, skipping restore" | logger -t hysteria2-iptables
        fi
    fi
fi

# Verify and restore IPv6 rules
if [ -f /etc/hy2config/iptables-rules.v6 ]; then
    if [ -s /etc/hy2config/iptables-rules.v6 ]; then
        if ip6tables-restore -t < /etc/hy2config/iptables-rules.v6 2>/dev/null; then
            ip6tables-restore < /etc/hy2config/iptables-rules.v6
            echo "IPv6 ip6tables rules restored successfully" | logger -t hysteria2-iptables
        else
            echo "IPv6 ip6tables rules file invalid, skipping restore" | logger -t hysteria2-iptables
        fi
    fi
fi

exit 0
"""
    restore_script_path = Path("/etc/hy2config/restore-iptables.sh")
    
    # Create systemd service
    service_content = """[Unit]
Description=Restore Hysteria2 iptables rules
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/hy2config/restore-iptables.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
"""
    service_path = Path("/etc/systemd/system/hysteria-iptables.service")
    try:
        # Write restore script
        restore_script_path.write_text(restore_script_content)
        restore_script_path.chmod(0o755)
        
        # Write service file
        service_path.write_text(service_content)
        
        # Reload systemd and enable service
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "hysteria-iptables.service"], check=True)
        print("iptables persistence service created")
    except Exception as e:
        print(f"\033[91mFailed to create iptables persistence service: {e}\033[m")

def save_iptables_rules():
    """Save current iptables and ip6tables rules"""
    try:
        # Create config directory
        config_dir = Path("/etc/hy2config")
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Save IPv4 rules
        with open("/etc/hy2config/iptables-rules.v4", "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True, text=True)
        print("IPv4 iptables rules saved")
        
        # Save IPv6 rules
        with open("/etc/hy2config/iptables-rules.v6", "w") as f:
            subprocess.run(["ip6tables-save"], stdout=f, check=True, text=True)
        print("IPv6 ip6tables rules saved")
        
        return True
    except Exception as e:
        print(f"\033[91mFailed to save iptables rules: {e}\033[m")
        return False

hy2_domain = "You are handsome"   # These variables are just to compliment you reading my code
domain_name = "Super handsome"
insecure = "You are really handsome"
def hysteria2_config():     # hysteria2 config
    global hy2_domain,domain_name, insecure
    hy2_config = Path(r"/etc/hysteria/config.yaml")  # Config file path
    hy2_url_scheme = Path(r"/etc/hy2config/hy2_url_scheme.txt")  # Config file path
    while True:
        choice_1 = input("1. View hy2 config\n2. One-key modify hy2 config\n3. Manually modify hy2 config\n4. Performance optimization (Optional, recommend installing xanmod kernel)\n0. Back\nEnter option: ")
        if choice_1 == "1":
            while True:
                    try:
                        os.system("clear")
                        print("Your official configuration file is:\n")
                        print(hy2_config.read_text())
                        print(hy2_url_scheme.read_text())
                        print("clash,surge,singbox templates are in /etc/hy2config/, please check manually\n")
                        break
                    except FileNotFoundError:     # Catch error if config file not found
                        print("\033[91mConfiguration file not found\033[m")
                    break
        elif choice_1 == "2":
            try:
                while True:
                    try:
                        hy2_port = int(input("Enter port number: "))
                        if hy2_port <= 0 or hy2_port >= 65536:
                            print("Port number range 1~65535, please re-enter")
                        else:
                            break
                    except ValueError:     # Catch error if input is not a number
                        print("Port number must be digits and cannot contain decimals, please re-enter")
                hy2_username = input("Enter your username:\n")
                hy2_username = urllib.parse.quote(hy2_username)
                hy2_passwd = input("Enter your strong password:\n")
                hy2_url = input("Enter your masquerade domain (please add https:// at the beginning):\n")
                while True:
                    hy2_brutal = input("Enable Brutal mode (Default not recommended)? [y/n]: ")
                    if hy2_brutal == "y":
                        brutal_mode = "false"
                        break
                    elif hy2_brutal == "n":
                        brutal_mode = "true"
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")
                while True:
                    hy2_obfs = input("Enable obfuscation mode (Default not recommended, will lose masquerade capability)? [y/n]: ")
                    if hy2_obfs == "y":
                        obfs_passwd = input("Enter your obfuscation password:\n")
                        obfs_mode = f"obfs:\n  type: salamander\n  \n  salamander:\n    password: {obfs_passwd}"
                        obfs_passwd = urllib.parse.quote(obfs_passwd)
                        obfs_scheme = f"&obfs=salamander&obfs-password={obfs_passwd}"
                        break
                    elif hy2_obfs == "n":
                        obfs_mode = ""
                        obfs_scheme = ""
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")
                while True:
                    hy2_sniff = input("Enable protocol sniffing (Sniff)[y/n]: ")
                    if hy2_sniff == "y":
                        sniff_mode = "sniff:\n  enable: true\n  timeout: 2s\n  rewriteDomain: false\n  tcpPorts: 80,443,8000-9000\n  udpPorts: all"
                        break
                    elif hy2_sniff == "n":
                        sniff_mode = ""
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")
                while True:
                    jump_port_choice = input("Enable port hopping (y/n): ")
                    if jump_port_choice == "y":
                        print("Please select your v4 network interface (default eth0, usually not lo)")
                        # Show available network interfaces
                        result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
                        if result.returncode == 0:
                            for line in result.stdout.strip().split('\n'):
                                # Extract interface name
                                if ':' in line:
                                    parts = line.split(':', 2)
                                    if len(parts) >= 2:
                                        print(f"  - {parts[1].strip()}")
                        interface_name = input("Enter your network interface name: ")
                        try:
                            first_port = int(input("Enter start port: "))
                            last_port = int(input("Enter end port: "))
                            if first_port <= 0 or first_port >= 65536:
                                print("Start port range 1~65535, please re-enter")
                            elif last_port <= 0 or last_port >= 65536:
                                print("End port range 1~65535, please re-enter")
                            elif first_port > last_port:
                                print("Start port cannot be greater than end port, please re-enter")
                            else:
                                # Init IPv6 variables
                                has_ipv6 = False
                                ipv6_interface = None
                                
                                while True:
                                    jump_port_ipv6 = input("Enable ipv6 port hopping (y/n): ")
                                    if jump_port_ipv6 == "y":
                                        print("Please select your v6 network interface:")
                                        # Show available network interfaces
                                        result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True)
                                        if result.returncode == 0:
                                            for line in result.stdout.strip().split('\n'):
                                                if ':' in line:
                                                    parts = line.split(':', 2)
                                                    if len(parts) >= 2:
                                                        print(f"  - {parts[1].strip()}")
                                        interface6_name = input("Enter your v6 network interface name: ")
                                        subprocess.run(["ip6tables", "-t", "nat", "-A", "PREROUTING", "-i", interface6_name,
                                                      "-p", "udp", "--dport", f"{first_port}:{last_port}",
                                                      "-j", "REDIRECT", "--to-ports", str(hy2_port)])
                                        # Record IPv6 info for cleanup script
                                        has_ipv6 = True
                                        ipv6_interface = interface6_name
                                        break
                                    elif jump_port_ipv6 == "n":
                                        has_ipv6 = False
                                        ipv6_interface = None
                                        break
                                    else:
                                        print("\033[91mInput error, please re-enter\033[m")
                                script_path = Path("/etc/hy2config/jump_port_back.sh")  # Check if restore script exists
                                if script_path.exists():
                                    subprocess.run(["/bin/bash", str(script_path)], stderr=subprocess.DEVNULL)
                                    script_path.unlink(missing_ok=True)
                                
                                # Apply iptables rules
                                subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", interface_name, 
                                              "-p", "udp", "--dport", f"{first_port}:{last_port}", 
                                              "-j", "REDIRECT", "--to-ports", str(hy2_port)])
                                
                                # Create cleanup script
                                jump_port_back = Path("/etc/hy2config/jump_port_back.sh")
                                cleanup_script = f"""#!/bin/sh
# Hysteria2 port hopping cleanup script
iptables -t nat -D PREROUTING -i {interface_name} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}
"""
                                if has_ipv6 and ipv6_interface:
                                    cleanup_script += f"ip6tables -t nat -D PREROUTING -i {ipv6_interface} -p udp --dport {first_port}:{last_port} -j REDIRECT --to-ports {hy2_port}\n"
                                
                                jump_port_back.write_text(cleanup_script)
                                jump_port_back.chmod(0o755)  # Safer permission setting
                                
                                # Save iptables rules for persistence
                                print("Saving iptables rules for auto-restore after reboot...")
                                if save_iptables_rules():
                                    # Create systemd service to restore rules on boot
                                    create_iptables_persistence_service()
                                    print("\033[92mPort hopping rules configured and persisted, will auto-restore after reboot\033[m")
                                else:
                                    print("\033[91mWarning: iptables rules applied but persistence failed, may need reconfiguration after reboot\033[m")
                                
                                jump_ports_hy2 = f"&mport={first_port}-{last_port}"
                                break
                        except ValueError:  # Catch error if input not integer
                            print("Port number must be digits and cannot contain decimals, please re-enter")
                    elif jump_port_choice == "n":
                        jump_ports_hy2 = ""
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")
                while True:

                    print("1. Auto apply for domain cert\n2. Use self-signed cert (no domain)\n3. Manual cert path")
                    choice_2 = input("Enter option: ")
                    if choice_2 == "1":
                        hy2_domain = input("Enter your domain:\n")
                        domain_name = hy2_domain
                        hy2_email = input("Enter your email:\n")
                        domain_name = ""
                        while True:
                            choice_acme = input("Configure ACME DNS (Skip if unsure) [y/n]: ")
                            if choice_acme == 'y':
                                while True:
                                    os.system('clear')
                                    dns_name = input("DNS Name:\n1.Cloudflare\n2.Duck DNS\n3.Gandi.net\n4.Godaddy\n5.Name.com\n6.Vultr\nEnter your option: ")
                                    if dns_name == '1':
                                        dns_token = input("Enter Cloudflare Global api_token: ")
                                        acme_dns = f"type: dns\n  dns:\n    name: cloudflare\n    config:\n      cloudflare_api_token: {dns_token}"
                                        break
                                    elif dns_name == '2':
                                        dns_token = input("Enter Duck DNS api_token: ")
                                        override_domain = input("Enter Duck DNS override_domain: ")
                                        acme_dns = f"type: dns\n  dns:\n    name: duckdns\n    config:\n      duckdns_api_token: {dns_token}\n    duckdns_override_domain: {override_domain}"
                                        break
                                    elif dns_name == '3':
                                        dns_token = input("Enter Gandi.net api_token: ")
                                        acme_dns = f"type: dns\n  dns:\n    name: gandi\n    config:\n      gandi_api_token: {dns_token}"
                                        break
                                    elif dns_name == '4':
                                        dns_token = input("Enter Godaddy api_token: ")
                                        acme_dns = f"type: dns\n  dns:\n    name: godaddy\n    config:\n      godaddy_api_token: {dns_token}"
                                        break
                                    elif dns_name == '5':
                                        dns_token = input("Enter Name.com namedotcom_token: ")
                                        dns_user = input("Enter Name.com namedotcom_user: ")
                                        namedotcom_server = input("Enter Name.com namedotcom_server: ")
                                        acme_dns = f"type: dns\n  dns:\n    name: {dns_name}\n    config:\n      namedotcom_token: {dns_token}\n      namedotcom_user: {dns_user}\n      namedotcom_server: {namedotcom_server}"
                                        break
                                    elif dns_name == '6':
                                        dns_token = input("Enter Vultr API Key: ")
                                        acme_dns = f"type: dns\n  dns:\n    name: {dns_name}\n    config:\n      vultr_api_key: {dns_token}"
                                        break
                                    else:
                                        print("Input error, please re-enter")
                                break
                            elif choice_acme == 'n':
                                acme_dns = ""
                                break
                            else:
                                print("Input error, please re-enter")
                        insecure = "&insecure=0"
                        hy2_config.write_text(f"listen: :{hy2_port} \n\nacme:\n  domains:\n    - {hy2_domain} \n  email: {hy2_email} \n  {acme_dns} \n\nauth:\n  type: password\n  password: {hy2_passwd} \n\nmasquerade: \n  type: proxy\n  proxy:\n    url: {hy2_url} \n    rewriteHost: true\n\nignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    elif choice_2 == "2":    # Get ipv4 address
                        def validate_and_get_ipv4():
                            """Helper function to get and validate IPv4 address from user"""
                            while True:
                                ip_input = input("Unable to auto-detect IP, please manually enter server IPv4: ").strip()
                                try:
                                    # Verify valid IPv4
                                    ipaddress.IPv4Address(ip_input)
                                    return ip_input
                                except ipaddress.AddressValueError:
                                    print(f"\033[91mInvalid IPv4: {ip_input}, please re-enter\033[m")
                        
                        def validate_and_get_ipv6():
                            """Helper function to get and validate IPv6 address from user"""
                            while True:
                                ip_input = input("Unable to auto-detect IP, please manually enter server IPv6: ").strip()
                                try:
                                    # Verify valid IPv6
                                    ipaddress.IPv6Address(ip_input)
                                    return ip_input
                                except ipaddress.AddressValueError:
                                    print(f"\033[91mInvalid IPv6: {ip_input}, please re-enter\033[m")
                        
                        def get_ipv4_info():
                            global hy2_domain
                            headers = {
                                'User-Agent': 'Mozilla'
                            }
                            try:
                                response = requests.get('http://ip-api.com/json/', headers=headers, timeout=3)
                                response.raise_for_status()
                                ip_data = response.json()
                                isp = ip_data.get('isp', '')

                                if 'cloudflare' in isp.lower():
                                    print("Warp detected, please enter correct server IPv4 address")
                                    hy2_domain = validate_and_get_ipv4()
                                else:
                                    hy2_domain = ip_data.get('query', '')

                                print(f"IPV4 WAN IP: {hy2_domain}")

                            except requests.RequestException as e:
                                print(f"Request failed: {e}")
                                print("Trying backup method to get IP...")
                                # Use backup method to get IP
                                try:
                                    result = subprocess.run(['curl', '-4', '-s', 'ifconfig.me'], capture_output=True, text=True, timeout=5)
                                    if result.returncode == 0 and result.stdout.strip():
                                        ip = result.stdout.strip()
                                        # Verify IPv4 format
                                        try:
                                            ipaddress.IPv4Address(ip)
                                            hy2_domain = ip
                                            print(f"IPV4 WAN IP: {hy2_domain}")
                                        except ipaddress.AddressValueError:
                                            # Invalid format, let user enter manually
                                            hy2_domain = validate_and_get_ipv4()
                                    else:
                                        # If failed, let user enter manually
                                        hy2_domain = validate_and_get_ipv4()
                                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, FileNotFoundError):
                                    # If backup method failed, let user enter manually
                                    hy2_domain = validate_and_get_ipv4()

                        def get_ipv6_info():    # Get ipv6 address
                            global hy2_domain
                            headers = {
                                'User-Agent': 'Mozilla'
                            }
                            try:
                                response = requests.get('https://api.ip.sb/geoip', headers=headers, timeout=3)
                                response.raise_for_status()
                                ip_data = response.json()
                                isp = ip_data.get('isp', '')

                                if 'cloudflare' in isp.lower():
                                    print("Warp detected, please enter correct server IPv6 address")
                                    ipv6_input = validate_and_get_ipv6()
                                    hy2_domain = f"[{ipv6_input}]"
                                else:
                                    hy2_domain = f"[{ip_data.get('ip', '')}]"

                                print(f"IPV6 WAN IP: {hy2_domain}")

                            except requests.RequestException as e:
                                print(f"Request failed: {e}")
                                print("Trying backup method to get IP...")
                                # Use backup method to get IPv6
                                try:
                                    result = subprocess.run(['curl', '-6', '-s', 'ifconfig.me'], capture_output=True, text=True, timeout=5)
                                    if result.returncode == 0 and result.stdout.strip():
                                        ip = result.stdout.strip()
                                        # Verify IPv6 format
                                        try:
                                            ipaddress.IPv6Address(ip)
                                            hy2_domain = f"[{ip}]"
                                            print(f"IPV6 WAN IP: {hy2_domain}")
                                        except ipaddress.AddressValueError:
                                            # Invalid format, let user enter manually
                                            ipv6_input = validate_and_get_ipv6()
                                            hy2_domain = f"[{ipv6_input}]"
                                    else:
                                        # If failed, let user enter manually
                                        ipv6_input = validate_and_get_ipv6()
                                        hy2_domain = f"[{ipv6_input}]"
                                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, FileNotFoundError):
                                    # If backup method failed, let user enter manually
                                    ipv6_input = validate_and_get_ipv6()
                                    hy2_domain = f"[{ipv6_input}]"

                        def generate_certificate():      # Generate self-signed certificate
                            global domain_name
                            # Prompt user for domain
                            user_domain = input("Enter domain for self-signed certificate (Default bing.com): ")
                            domain_name = user_domain.strip() if user_domain else "bing.com"

                            # Verify domain format
                            if re.match(r'^[a-zA-Z0-9.-]+$', domain_name):
                                # Define target directory
                                target_dir = "/etc/ssl/private"

                                # Check and create target directory
                                if not os.path.exists(target_dir):
                                    print(f"Target directory {target_dir} does not exist, creating...")
                                    os.makedirs(target_dir)
                                    if not os.path.exists(target_dir):
                                        print(f"Failed to create directory {target_dir}, please check permissions.")
                                        exit(1)

                                # Generate EC param file
                                ec_param_file = f"{target_dir}/ec_param.pem"
                                subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-out", ec_param_file],
                                               check=True)

                                # Generate certificate and private key
                                cmd = [
                                    "openssl", "req", "-x509", "-nodes", "-newkey", f"ec:{ec_param_file}",
                                    "-keyout", f"{target_dir}/{domain_name}.key",
                                    "-out", f"{target_dir}/{domain_name}.crt",
                                    "-subj", f"/CN={domain_name}", "-days", "36500"
                                ]
                                subprocess.run(cmd, check=True)

                                # Set file permissions
                                os.system(f"chmod 666 {target_dir}/{domain_name}.key && chmod 666 {target_dir}/{domain_name}.crt && chmod 777 /etc/ssl/private/")

                                print("Self-signed certificate and private key generated!")
                                print(f"Certificate file saved to {target_dir}/{domain_name}.crt")
                                print(f"Private key file saved to {target_dir}/{domain_name}.key")
                            else:
                                print("Invalid domain format, please enter a valid domain!")
                                generate_certificate()

                        generate_certificate()
                        while True:
                            ip_mode = input("1. ipv4 mode\n2. ipv6 mode\nEnter your option: ")
                            if ip_mode == '1':
                                get_ipv4_info()
                                break
                            elif ip_mode == '2':
                                get_ipv6_info()
                                break
                            else:
                                print("\033[91mInput error, please re-enter!\033[m")
                        insecure = "&insecure=1"
                        hy2_config.write_text(f"listen: :{hy2_port} \n\ntls: \n  cert: /etc/ssl/private/{domain_name}.crt \n  key: /etc/ssl/private/{domain_name}.key \n\nauth: \n  type: password \n  password: {hy2_passwd} \n\nmasquerade: \n  type: proxy \n  proxy: \n    url: {hy2_url} \n    rewriteHost: true \n\nignoreClientBandwidth: {brutal_mode} \n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    elif choice_2 == "3":
                        hy2_cert = input("Enter your certificate path:\n")
                        hy2_key = input("Enter your private key path:\n")
                        hy2_domain = input("Enter your domain:\n")
                        domain_name = hy2_domain
                        domain_name = ""
                        insecure = "&insecure=0"
                        hy2_config.write_text(f"listen: :{hy2_port}\n\ntls:\n  cert: {hy2_cert}\n  key: {hy2_key}\n\nauth:\n  type: password\n  password: {hy2_passwd}\n\nmasquerade: \n  type: proxy\n  proxy:\n    url: {hy2_url}\n    rewriteHost: true\n\nignoreClientBandwidth: {brutal_mode}\n\n{obfs_mode}\n{sniff_mode}\n")
                        break
                    else:
                        print("\033[91mInput error, please re-enter\033[m")

                os.system("clear")
                hy2_passwd = urllib.parse.quote(hy2_passwd)
                hy2_v2ray = f"hysteria2://{hy2_passwd}@{hy2_domain}:{hy2_port}?sni={domain_name}{obfs_scheme}{insecure}{jump_ports_hy2}#{hy2_username}"
                print("Your v2ray QR code is:\n")
                time.sleep(1)
                os.system(f'echo "{hy2_v2ray}" | qrencode -s 1 -m 1 -t ANSI256 -o -')
                print(f"\n\n\033[91mYour hy2 link is: {hy2_v2ray}\nPlease import using v2ray/nekobox/v2rayNG/nekoray software\033[m\n\n")
                hy2_url_scheme.write_text(f"Your v2ray hy2 config link is: {hy2_v2ray}\n")
                print("Downloading clash, sing-box, surge config files to /etc/hy2config/clash.yaml")
                hy2_v2ray_url = urllib.parse.quote(hy2_v2ray)
                url_rule = "&ua=&selectedRules=%22balanced%22&customRules=%5B%5D"
                os.system(f"curl -o /etc/hy2config/clash.yaml 'https://sub.baibaicat.site/clash?config={hy2_v2ray_url}{url_rule}'")
                os.system(f"curl -o /etc/hy2config/sing-box.yaml 'https://sub.baibaicat.site/singbox?config={hy2_v2ray_url}{url_rule}'")
                os.system(f"curl -o /etc/hy2config/surge.yaml 'https://sub.baibaicat.site/surge?config={hy2_v2ray_url}{url_rule}'")
                print("\033[91m \nclash,sing-box,surge config files saved to /etc/hy2config/ directory !!\n\n \033[m")
                os.system("systemctl enable --now hysteria-server.service")
                os.system("systemctl restart hysteria-server.service")

            except FileNotFoundError:
                print("\033[91mConfig file not found, please install hysteria2 first\033[m")
        elif choice_1 == "3":
            print("\033[91mUsing nano editor for manual modification, press Ctrl+X to save and exit\033[m")
            print(subprocess.run("nano /etc/hysteria/config.yaml",shell=True))   # Call nano editor manual modification
            os.system("systemctl enable --now hysteria-server.service")
            os.system("systemctl restart hysteria-server.service")
            print("hy2 service started")
        elif choice_1 == "4":
            os.system("wget -O tcpx.sh 'https://github.com/ylx2016/Linux-NetSpeed/raw/master/tcpx.sh' && chmod +x tcpx.sh && ./tcpx.sh")
        elif choice_1 == "0":
            break
        else:
            print("\033[91mPlease re-enter\033[m")


def check_hysteria2_version():  # Check hysteria2 version
    try:
        output = subprocess.check_output("/usr/local/bin/hysteria version | grep '^Version' | grep -o 'v[.0-9]*'",shell=True, stderr=subprocess.STDOUT)
        version = output.decode('utf-8').strip()

        if "v" in version:
            print(f"Current hysteria2 version is: {version}")
        else:
            print("hysteria2 version not found")
    except subprocess.CalledProcessError as e:
        print(f"Command execution failed: {e.output.decode('utf-8')}")

# Main program starts
agree_treaty()
while True:
    os.system("clear")
    print("\033[91mHELLO HYSTERIA2 !\033[m  (Type hy2 for quick start)")  # Red text output
    print("1. Install/Update hysteria2\n2. Uninstall hysteria2\n3. hysteria2 config\n4. hysteria2 service management\n0. Exit")
    choice = input("Enter option: ")
    if choice == "1":
        os.system("clear")
        hysteria2_install()
    elif choice == "2":
        os.system("clear")
        hysteria2_uninstall()
    elif choice == "3":
        os.system("clear")
        hysteria2_config()
    elif choice == "4":
        os.system("clear")
        check_hysteria2_version()
        server_manage()
    elif choice == "0":
        print("Exited")
        sys.exit()
    else:
        print("\033[91mInput error, please re-enter\033[m")
        time.sleep(1)



