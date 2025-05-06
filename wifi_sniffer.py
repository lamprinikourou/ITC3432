from scapy.all import *
from datetime import datetime

# Lists to store unique entries
seen_beacons = set()
seen_deauths = set()
seen_macs = set()

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        mac_ap = pkt[Dot11].addr2
        mac_sta = pkt[Dot11].addr1

        # 1. Beacon frames (type=0, subtype=8)
        if pkt.type == 0 and pkt.subtype == 8:
            ssid = pkt.info.decode(errors='ignore') if pkt.haslayer(Dot11Elt) else "<hidden>"
            if (mac_ap, ssid) not in seen_beacons:
                seen_beacons.add((mac_ap, ssid))
                print(f"[BEACON] {ssid} ({mac_ap}) - {datetime.now().strftime('%H:%M:%S')}")

        # 2. Deauthentication frames (type=0, subtype=12)
        elif pkt.type == 0 and pkt.subtype == 12:
            if (mac_ap, mac_sta) not in seen_deauths:
                seen_deauths.add((mac_ap, mac_sta))
                print(f"[DEAUTH] From AP {mac_ap} to STA {mac_sta} - {datetime.now().strftime('%H:%M:%S')}")

        # 3. Any frame revealing STA MAC (e.g. Probe Requests, Auth, Assoc, Data)
        elif pkt.addr1 and pkt.addr2:
            if pkt.addr1 not in seen_macs and pkt.addr1 != 'ff:ff:ff:ff:ff:ff':
                seen_macs.add(pkt.addr1)
                print(f"[STA DETECTED] MAC: {pkt.addr1} - {datetime.now().strftime('%H:%M:%S')}")

print("Sniffing on interface 'wlan0mon'... Press Ctrl+C to stop.")
sniff(iface="wlan0mon", prn=packet_handler, store=0)
