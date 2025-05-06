from scapy.all import *
from datetime import datetime

# Path to local capture file (update as needed)
CAPTURE_FILE = "/Users/lamprinikourou/Downloads/Capture.pcapng"

# Sets to avoid duplicate logs
seen_beacons = set()
seen_deauths = set()
seen_macs = set()

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        mac_ap = pkt[Dot11].addr2
        mac_sta = pkt[Dot11].addr1

        # Beacon frame
        if pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info.decode(errors='ignore') if pkt.haslayer(Dot11Elt) else "<hidden>"
            if (mac_ap, ssid) not in seen_beacons:
                seen_beacons.add((mac_ap, ssid))
                print(f"[BEACON] {ssid} ({mac_ap}) - {datetime.now().strftime('%H:%M:%S')}")

        # Deauthentication frame
        elif pkt.type == 0 and pkt.subtype == 12:
            if (mac_ap, mac_sta) not in seen_deauths:
                seen_deauths.add((mac_ap, mac_sta))
                print(f"[DEAUTH] From AP {mac_ap} to STA {mac_sta} - {datetime.now().strftime('%H:%M:%S')}")

        # General frame revealing STA MAC
        elif pkt.addr1 and pkt.addr1 != 'ff:ff:ff:ff:ff:ff':
            if pkt.addr1 not in seen_macs:
                seen_macs.add(pkt.addr1)
                print(f"[STA DETECTED] MAC: {pkt.addr1} - {datetime.now().strftime('%H:%M:%S')}")

# Read and process packets from capture file
print(f"Processing capture file: {CAPTURE_FILE}")
packets = rdpcap(CAPTURE_FILE)
for pkt in packets:
    packet_handler(pkt)
