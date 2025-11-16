import os
import sys
import subprocess
import time
import re
import getpass

# --- Configuration ---
CONFIG_FILE = "/tmp/wpa_supplicant_temp.conf"
INTERFACE_NAME = None

def check_root():
    """Exits the script if not run as root."""
    if os.geteuid() != 0:
        print("🚨 ERROR: This script must be run with root privileges (sudo).")
        print("Usage: sudo python3 wifi_connect.py")
        sys.exit(1)

def run_command(cmd, check_result=True, error_msg=None):
    """A helper function to run shell commands."""
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check_result,
            shell=False
        )
        return process
    except subprocess.CalledProcessError as e:
        if check_result:
            print(f"🚨 ERROR: {error_msg if error_msg else 'Command failed.'}")
            print(f"Command: {' '.join(cmd)}")
            print(f"Stderr: {e.stderr.strip()}")
            sys.exit(1)
        return e
    except FileNotFoundError:
        print(f"🚨 ERROR: The command '{cmd[0]}' was not found.")
        print("Ensure required tools (ip, iw, wpa_supplicant, dhclient) are installed.")
        sys.exit(1)

def get_wireless_interface():
    """Finds the name of the wireless interface."""
    print("Searching for wireless interface...")
    try:
        result = run_command(['iw', 'dev'], check_result=True)
        
        # Parse output to find Interface name
        for line in result.stdout.split('\n'):
            if 'Interface' in line:
                match = re.search(r'Interface\s+(\S+)', line)
                if match:
                    iface = match.group(1)
                    print(f"✅ Found wireless interface: {iface}")
                    return iface
        
        print("🚨 ERROR: No wireless interface found. Check if your driver is loaded.")
        sys.exit(1)
    except Exception as e:
        print(f"🚨 ERROR during interface detection: {e}")
        sys.exit(1)

def scan_networks(interface):
    """Scans for available WiFi networks and returns a list of unique SSIDs with their signal strength."""
    print(f"\n🔍 Scanning for WiFi networks on {interface}...\n")
    
    # Trigger a scan
    run_command(['ip', 'link', 'set', interface, 'up'], check_result=False)
    time.sleep(1)
    
    scan_trigger = run_command(['iw', interface, 'scan'], check_result=False)
    
    if not scan_trigger or scan_trigger.returncode != 0:
        print("⚠️  Warning: Scan command failed. Trying again...")
        time.sleep(2)
        scan_trigger = run_command(['iw', interface, 'scan'], check_result=True, 
                                   error_msg="Failed to scan for networks.")
    
    # Parse scan results
    networks = {}
    current_ssid = None
    current_signal = None
    
    for line in scan_trigger.stdout.split('\n'):
        line = line.strip()
        
        # Look for SSID
        if line.startswith('SSID:'):
            current_ssid = line.replace('SSID:', '').strip()
        
        # Look for signal strength
        if 'signal:' in line:
            signal_match = re.search(r'signal:\s+([-\d.]+)', line)
            if signal_match:
                current_signal = float(signal_match.group(1))
        
        # When we have both SSID and signal, store it
        if current_ssid and current_signal is not None:
            # Only keep the strongest signal if we see the same SSID multiple times
            if current_ssid not in networks or current_signal > networks[current_ssid]:
                networks[current_ssid] = current_signal
            current_ssid = None
            current_signal = None
    
    # Remove empty SSIDs and sort by signal strength
    networks = {ssid: signal for ssid, signal in networks.items() if ssid}
    sorted_networks = sorted(networks.items(), key=lambda x: x[1], reverse=True)
    
    return sorted_networks

def display_networks(networks):
    """Displays the list of networks with numbers for selection."""
    print("Available WiFi Networks:")
    print("=" * 60)
    print(f"{'#':<4} {'SSID':<35} {'Signal (dBm)':<15}")
    print("-" * 60)
    
    for idx, (ssid, signal) in enumerate(networks, 1):
        # Signal strength indicator
        if signal > -50:
            strength = "Excellent"
        elif signal > -60:
            strength = "Good"
        elif signal > -70:
            strength = "Fair"
        else:
            strength = "Weak"
        
        print(f"{idx:<4} {ssid:<35} {signal:>6.1f} ({strength})")
    
    print("=" * 60)

def get_user_selection(networks):
    """Prompts user to select a network."""
    while True:
        try:
            choice = input(f"\nSelect network (1-{len(networks)}) or 'q' to quit: ").strip()
            
            if choice.lower() == 'q':
                print("Exiting...")
                sys.exit(0)
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(networks):
                return networks[choice_num - 1][0]  # Return SSID
            else:
                print(f"⚠️  Please enter a number between 1 and {len(networks)}")
        except ValueError:
            print("⚠️  Invalid input. Please enter a number or 'q' to quit.")
        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)

def get_password():
    """Prompts user to enter password securely."""
    while True:
        try:
            password = getpass.getpass("Enter WiFi password (or press Enter for open network): ")
            return password
        except KeyboardInterrupt:
            print("\n\nExiting...")
            sys.exit(0)

def create_config(ssid, password):
    """Creates wpa_supplicant configuration file."""
    print(f"\nGenerating configuration for '{ssid}'...")
    
    try:
        if password:
            # WPA/WPA2 network with password
            wpa_passphrase_cmd = ['wpa_passphrase', ssid, password]
            wpa_result = subprocess.run(
                wpa_passphrase_cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Filter out clear-text password comment
            config_content = "\n".join([
                line for line in wpa_result.stdout.splitlines()
                if not line.strip().startswith('#psk=')
            ]) + "\n"
        else:
            # Open network (no password)
            config_content = f"""network={{
    ssid="{ssid}"
    key_mgmt=NONE
}}
"""
        
        # Write config file
        with open(CONFIG_FILE, 'w') as f:
            f.write(config_content)
        
        # Set restrictive permissions
        os.chmod(CONFIG_FILE, 0o600)
        print("✅ Configuration file created")
        
    except subprocess.CalledProcessError as e:
        print(f"🚨 ERROR: Failed to generate configuration.")
        print(f"Stderr: {e.stderr.strip()}")
        sys.exit(1)
    except Exception as e:
        print(f"🚨 ERROR: Could not write configuration file: {e}")
        sys.exit(1)

def connect_to_network(interface, ssid):
    """Connects to the selected WiFi network."""
    
    # Clean up old processes
    print("\n🔧 Stopping any running wpa_supplicant processes...")
    run_command(['pkill', 'wpa_supplicant'], check_result=False)
    time.sleep(1)
    
    # Bring interface up
    print(f"🔧 Bringing interface {interface} up...")
    run_command(['ip', 'link', 'set', interface, 'up'], check_result=False)
    time.sleep(1)
    
    # Start wpa_supplicant
    print(f"🔧 Starting wpa_supplicant for '{ssid}'...")
    wpa_cmd = [
        'wpa_supplicant',
        '-B',
        '-i', interface,
        '-c', CONFIG_FILE,
        '-D', 'nl80211'
    ]
    
    wpa_result = run_command(wpa_cmd, check_result=False)
    
    if wpa_result and wpa_result.returncode != 0:
        print("⚠️  wpa_supplicant returned non-zero code, but may still work...")
    
    # Wait for association
    print("⏳ Waiting for authentication (10 seconds)...")
    time.sleep(10)
    
    # Request IP via DHCP
    print("🔧 Requesting IP address...")
    run_command(['dhclient', '-r', interface], check_result=False)
    time.sleep(1)
    run_command(['dhclient', '-v', interface], check_result=False)
    time.sleep(2)
    
    # Verify connection
    print("\n🔍 Verifying connection...")
    ip_result = run_command(['ip', 'addr', 'show', 'dev', interface], check_result=True)
    ip_match = re.search(r'inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', ip_result.stdout)
    
    if ip_match:
        ip_addr = ip_match.group(1)
        print("\n" + "=" * 50)
        print("✅ CONNECTION SUCCESSFUL!")
        print("=" * 50)
        print(f"SSID:      {ssid}")
        print(f"Interface: {interface}")
        print(f"IP:        {ip_addr}")
        print("=" * 50)
        
        # Check connection details
        iw_result = run_command(['iw', 'dev', interface, 'link'], check_result=False)
        if iw_result and iw_result.returncode == 0:
            print("\nConnection Details:")
            print(iw_result.stdout)
        
        # Test internet
        print("🌐 Testing internet connectivity...")
        ping_result = run_command(['ping', '-c', '3', '-W', '5', '8.8.8.8'], check_result=False)
        if ping_result and ping_result.returncode == 0:
            print("✅ Internet is working!\n")
        else:
            print("⚠️  No internet access detected. Network may require additional authentication.\n")
        
        return True
    else:
        print("\n" + "=" * 50)
        print("❌ CONNECTION FAILED")
        print("=" * 50)
        print("Could not obtain an IP address.")
        print("\nPossible issues:")
        print("• Incorrect password")
        print("• Network requires additional authentication (captive portal)")
        print("• DHCP server not responding")
        print("• MAC address filtering enabled on router")
        print("\nTry connecting to a different network or check the password.")
        print("=" * 50 + "\n")
        return False

def main():
    global INTERFACE_NAME
    
    check_root()
    
    print("=" * 60)
    print("WiFi Connection Manager (NetworkManager-Free)")
    print("=" * 60)
    
    # Find wireless interface
    INTERFACE_NAME = get_wireless_interface()
    
    # Scan for networks
    networks = scan_networks(INTERFACE_NAME)
    
    if not networks:
        print("🚨 No WiFi networks found. Check if your wireless card is enabled.")
        sys.exit(1)
    
    # Display networks
    display_networks(networks)
    
    # Get user selection
    selected_ssid = get_user_selection(networks)
    print(f"\n📡 Selected network: {selected_ssid}")
    
    # Get password
    password = get_password()
    
    # Create configuration
    create_config(selected_ssid, password)
    
    # Clear password from memory
    del password
    
    # Connect
    success = connect_to_network(INTERFACE_NAME, selected_ssid)
    
    if success:
        print("To disconnect, run: sudo pkill wpa_supplicant && sudo dhclient -r", INTERFACE_NAME)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
