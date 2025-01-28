import socket
import struct

# Create raw socket (promiscuous mode)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

while True:
    raw_packet, addr = s.recvfrom(65535)
    
    # Parse Ethernet header (first 14 bytes)
    eth_header = raw_packet[:14]
    eth = struct.unpack('!6s6sH', eth_header)  # Dest MAC, Source MAC, Type
    eth_proto = socket.ntohs(eth[2])
    print(f"[ETH] Destination: {eth[0].hex()}, Source: {eth[1].hex()}, Protocol: {eth_proto}")
    
    # Parse IP header (starts at byte 14)
    if eth_proto == 0x0800:  # IPv4
        ip_header = raw_packet[14:34]
        ip = struct.unpack('!BBHHHBBH4s4s', ip_header)
        ttl = ip[5]
        proto = ip[6]
        src_ip = socket.inet_ntoa(ip[8])
        dst_ip = socket.inet_ntoa(ip[9])
        print(f"[IP] {src_ip} -> {dst_ip} | Protocol: {proto}, TTL: {ttl}")
        
        # Parse TCP (protocol 6)
        if proto == 6 and len(raw_packet) >= 34:
            tcp_header = raw_packet[34:54]
            tcp = struct.unpack('!HHLLBBHHH', tcp_header)
            src_port = tcp[0]
            dst_port = tcp[1]
            print(f"  [TCP] Port: {src_port} -> {dst_port}")
        
        # Parse UDP (protocol 17)
        elif proto == 17 and len(raw_packet) >= 34:
            udp_header = raw_packet[34:42]
            udp = struct.unpack('!HHHH', udp_header)
            src_port = udp[0]
            dst_port = udp[1]
            print(f"  [UDP] Port: {src_port} -> {dst_port}")