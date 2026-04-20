WiFi Connection Manager — Evil-Twin Aware Edition

A hardened, standalone Python-based WiFi connection utility for Linux. This tool moves beyond simple scanning by implementing an Evil-Twin detection engine and a BSSID Trust Store to protect against rogue access points and man-in-the-middle (MITM) attacks.
🛡️ Security Features
1. Trusted-BSSID Store

The script maintains a local database of known-good hardware addresses at ~/.config/wifi-guardian/trusted_bssids.json.

    First Visit: When you successfully connect to a new SSID, its BSSID is saved.

    Subsequent Visits: Every observed BSSID is compared against the trusted record. If a known SSID suddenly appears with a different BSSID, the script flags it immediately.

2. Multi-Layer Threat Analysis

During every scan, the tool applies three heuristic rules to identify potential "Evil Twins":

    LA-bit Rule (CRITICAL): Detects BSSIDs with the "Locally Administered" bit set (indicating a software-defined MAC address). Unless previously trusted, these are blocked outright.

    Clone Rule (HIGH): Identifies pairs of BSSIDs that differ by only 1 or 2 octets. This is a common indicator of an attacker mimicking a legitimate network or a rogue AP mimicking a multi-node mesh system.

    Signal Spread (MEDIUM): Flags SSIDs broadcasting on multiple channels with a significant signal strength delta (>10 dBm), which can indicate a nearby rogue device attempting to overpower a legitimate AP.

3. Connection Gatekeeping

    Blocked Access: Networks flagged as CRITICAL cannot be joined through the script.

    Override Protection: Networks with HIGH or MEDIUM warnings require explicit user confirmation or a "yes" override to proceed.

    Post-Connect Verification: After gaining an IP address, the tool re-verifies the connected BSSID. If the AP switched or spoofed the BSSID during the handshake, it alerts the user to disconnect immediately.

🚀 Requirements

    OS: Linux (tested on Debian/Ubuntu/Kali)

    Privileges: Must be run as root (sudo) to manage network interfaces.

    Dependencies:

        iw: For scanning and link status.

        wpa_supplicant / wpa_passphrase: For authentication.

        dhclient: For obtaining IP addresses.

        iproute2: For interface management.

🛠️ Usage

    Clone the repository:
    Bash

git clone https://github.com/microlaser/Standalone_WiFi_Scanner.git
cd Standalone_WiFi_Scanner

Run the manager:
Bash

    sudo python3 wifi-connect3.py

    Interact:

        Select a network from the numbered list.

        Observe the Status column for Trusted, First-time, or Suspicious indicators.

        If prompted, enter the WPA2 passphrase.

📁 File Structure

    wifi-connect3.py: The main executable script.

    ~/.config/wifi-guardian/: Directory where the BSSID trust store is maintained (created on first run).

    /tmp/wpa_supplicant_temp.conf: A temporary, permission-hardened (0600) config file generated during the connection process.

⚖️ Disclaimer

This tool is designed for security-conscious users and forensic investigators. While it provides significant protection against common WiFi attacks, it is not a substitute for a VPN or end-to-end encryption. Always verify your network environment when handling sensitive data.
