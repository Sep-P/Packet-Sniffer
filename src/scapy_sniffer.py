from scapy.all import *

def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        print(f"[IP] {src_ip} -> {dst_ip} | Protocol: {proto}")

        # Parse TCP/UDP
        if packet.haslayer(TCP):
            print(f"  [TCP] Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"  [UDP] Port: {packet[UDP].sport} -> {packet[UDP].dport}")

# Start sniffing (stop after 10 packets)
sniff(prn=packet_handler, count=10)