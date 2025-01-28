# Packet Header Breakdown

Understanding packet headers is critical for network analysis, intrusion detection, and low-level cybersecurity work. Below is a byte-by-byte breakdown of Ethernet, IPv4, TCP, and UDP headers.

---

## **Ethernet Frame Header (Layer 2)**
**Length**: 14 bytes  
**Structure**:
0 6 12 14 (bytes)
+--------------------+--------------------+--------------------+
| Destination MAC | Source MAC | EtherType |
| (6 bytes) | (6 bytes) | (2 bytes) |
+--------------------+--------------------+--------------------+


### **Field Descriptions**
| Field           | Size (bytes) | Description                                                                 |
|-----------------|--------------|-----------------------------------------------------------------------------|
| Destination MAC | 6            | MAC address of the recipient (e.g., `00:1a:2b:3c:4d:5e`).                  |
| Source MAC      | 6            | MAC address of the sender.                                                 |
| EtherType       | 2            | Protocol encapsulated in the payload (e.g., `0x0800` for IPv4, `0x0806` for ARP). |

### **Example Hex Dump**
00 1A 2B 3C 4D 5E 00 A1 B2 C3 D4 E5 08 00

- **Destination MAC**: `00:1a:2b:3c:4d:5e`  
- **Source MAC**: `00:a1:b2:c3:d4:e5`  
- **EtherType**: `0x0800` (IPv4)

---

## **IPv4 Header (Layer 3)**
**Length**: 20 bytes (minimum, can be longer with options)  
**Structure**:
0 1 2 3 (bytes)
+--------+--------+--------+--------+--------+--------+--------+--------+
|Version | IHL | TOS | Total Length | |
|(4 bits)|(4 bits)| (1 byte) (2 bytes) | |
+--------+--------+--------+--------+--------+--------+--------+--------+
| Identification | Flags | Fragment Offset | |
| (2 bytes) |(3 bits) (13 bits) | |
+--------+--------+--------+--------+--------+--------+--------+--------+
| TTL | Protocol | Header Checksum | Source IP Address |
|(1 byte)| (1 byte) | (2 bytes) | (4 bytes) |
+--------+--------+--------+--------+--------+--------+--------+--------+
| Destination IP Address | Options (if IHL > 5) |
| (4 bytes) | (variable length) |
+-----------------------------------+-----------------------------+


### **Key Fields**
| Field           | Size    | Description                                                                 |
|-----------------|---------|-----------------------------------------------------------------------------|
| Version         | 4 bits  | IP version (`4` for IPv4).                                                 |
| IHL             | 4 bits  | Header length in 32-bit words (e.g., `5` = 20 bytes).                      |
| TTL             | 1 byte  | Time to Live (prevents infinite loops). Decremented at each router hop.    |
| Protocol        | 1 byte  | Layer 4 protocol (`6` = TCP, `17` = UDP).                                  |
| Source/Dest IP  | 4 bytes | IPv4 addresses in dotted decimal format (e.g., `192.168.1.1`).             |

### **Hex Dump Example**
45 00 00 34 12 34 00 00 40 06 9A 8B C0 A8 01 01 C0 A8 01 02

- **Version/IHL**: `4` (IPv4) and `5` (20-byte header).  
- **Protocol**: `0x06` (TCP).  
- **Source IP**: `192.168.1.1` (`C0 A8 01 01`).  
- **Dest IP**: `192.168.1.2` (`C0 A8 01 02`).

---

## **TCP Header (Layer 4)**
**Length**: 20 bytes (minimum, up to 60 bytes with options)  
**Structure**:
0 1 2 3 (bytes)
+--------+--------+--------+--------+--------+--------+--------+--------+
| Source Port | Destination Port | |
| (2 bytes) | (2 bytes) | |
+--------+--------+--------+--------+--------+--------+--------+--------+
| Sequence Number | |
| (4 bytes) | |
+--------+--------+--------+--------+--------+--------+--------+--------+
| Acknowledgment Number | |
| (4 bytes) | |
+--------+--------+--------+--------+--------+--------+--------+--------+
| Data | Reserved| Flags | Window Size | |
| Offset| |(URG ACK| (2 bytes) | |
|(4 bits| (6 bits) PSH RST | | |
| | SYN FIN) | | |
+--------+--------+--------+--------+--------+--------+--------+--------+
| Checksum | Urgent Pointer | Options (if Data Offset > 5) |
| (2 bytes) | (2 bytes) | (variable length) |
+------------------+-----------------+-----------------------------------+


### **Key Fields**
| Field           | Size    | Description                                                                 |
|-----------------|---------|-----------------------------------------------------------------------------|
| Source/Dest Port| 2 bytes | Port numbers (e.g., `80` for HTTP).                                         |
| Flags           | 1 byte  | Control flags (e.g., `SYN=0x02`, `ACK=0x10`).                              |
| Checksum        | 2 bytes | Covers TCP header, data, and a pseudo-header from the IP layer.            |

### **Hex Dump Example**
C6 9F 00 50 00 00 00 00 00 00 00 00 50 02 20 00 91 7C 00 00

- **Source Port**: `50847` (`C6 9F`).  
- **Dest Port**: `80` (`00 50`).  
- **Flags**: `0x02` (SYN flag set).

---

## **UDP Header (Layer 4)**
**Length**: 8 bytes  
**Structure**:
0 1 2 3 (bytes)
+--------+--------+--------+--------+--------+--------+--------+--------+
| Source Port | Destination Port | |
| (2 bytes) | (2 bytes) | |
+--------+--------+--------+--------+--------+--------+--------+--------+
| Length | Checksum | |
| (2 bytes) | (2 bytes) | |
+--------+--------+--------+--------+--------+--------+--------+--------+


### **Key Fields**
| Field           | Size    | Description                                                                 |
|-----------------|---------|-----------------------------------------------------------------------------|
| Source/Dest Port| 2 bytes | Port numbers (e.g., `53` for DNS).                                          |
| Length          | 2 bytes | Total length of UDP header + data.                                          |
| Checksum        | 2 bytes | Optional in IPv4, mandatory in IPv6.                                        |

### **Hex Dump Example**
D3 4F 00 35 00 21 2D 4E

- **Source Port**: `54159` (`D3 4F`).  
- **Dest Port**: `53` (`00 35`) (DNS).  
- **Length**: `33` bytes (`00 21`).

---

## **Why Manual Parsing Matters**
1. **Security Analysis**: Detect packet manipulation (e.g., spoofed headers).  
2. **Forensics**: Identify malicious traffic patterns.  
3. **Performance**: Low-level tools avoid overhead from libraries like Scapy.  

For code examples, see [`raw_socket_sniffer.py`](../src/raw_socket_sniffer.py).

