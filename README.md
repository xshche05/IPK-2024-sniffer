# ZETA - Network Packet Sniffer

An IPK course project, network packet sniffer

## Introduction
A sniffer application, also known as a packet analyzer or network analyzer, is a software tool used to monitor and
analyze network traffic in real-time. It captures packets traversing a network interface, allowing users to inspect,
analyze, and troubleshoot network communications. Sniffer applications are widely used for various purposes such as
network troubleshooting. This project aims to implement a simple sniffer application that can capture and analyze
network packets according to the user's requirements. All captured packets' data is parsed according to packet type
specification and printed to the standard output in a human-readable format.

## Technologies involved

### Packet capturing
- **Libpcap**: This is library that provide packet capture capabilities on Unix-like systems.
They allow the sniffer application to capture packets from the network interface.

- **Promiscuous Mode**: This mode allows the network interface to capture all packets on the network, regardless of their 
destination MAC address. It is essential for sniffing traffic not intended for the host.

### Protocol analysis
- **Ethernet**: The Ethernet protocol is used to transmit data packets between network devices. It is the most common
data link layer protocol used in local area networks (LANs). The sniffer application must be able to parse Ethernet
headers to extract information such as source and destination MAC addresses.
- **IPv4/IPv6**: The Internet Protocol (IP) is used to route data packets across networks. The sniffer application must
be able to parse IP headers to extract information such as source and destination IP addresses.
- **ICMPv4/ICMPv6**: The Internet Control Message Protocol (ICMP) is used to send error messages and operational
information between network devices. The sniffer application must be able to parse ICMP headers to extract information and 
in case of ICMPv6, it must be able to distinguish between different types of ICMPv6 packets.
- **ARP/NDP**: The Address Resolution Protocol (ARP) and Neighbor Discovery Protocol (NDP) are used to map IP addresses
to MAC addresses on local networks.
- **IGMP/MLD**: The Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) are used to manage
multicast group membership on local networks.
- **TCP/UDP**: The Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) are used to transmit data between
network devices. The sniffer application must be able to parse TCP and UDP headers to extract information such as source
and destination port numbers.

### Implementation
- The sniffer application needs to utilize a packet capture library like Libpcap to capture packets from the network 
interface specified with -i or --interface.
- It then applies filtering based on the specified parameters to select the desired packets for display.
- The application analyzes the packet headers according to the selected protocols and functionalities to extract relevant information.
- Finally, it displays the filtered packets in a human-readable format to the standard output.

## Tests
In this section, we will describe the tests that were performed on the sniffer. For testing purposes, `wireshark` is used 
to capture packets and send them to the network. The sniffer was then used to capture the packets and print the output.
Following tests were performed:

- TCP capture
- UDP capture
- ARP capture
- IGMP capture
- ICMPv4 capture
- ICMPv6 Echo/Reply capture
- MLD capture
- NDP capture

Some of most complex test cases is described in the following sections. Other test cases were successfully tested and are not
described here in detail.
### MLD Test
#### Description
Test checks if sniffer is able to correctly recognise MDL packets, and do not recognise it as `icmp6` packets.
#### Sent packet
Following packet (dump from wireshark) was sent to the network:
```hexdump
0000   33 33 00 00 00 16 00 15 5d a0 4d 73 86 dd 60 00
0010   00 00 00 18 3a 01 fe 80 00 00 00 00 00 00 02 15
0020   5d ff fe a0 4d 73 ff 02 00 00 00 00 00 00 00 00
0030   00 00 00 00 00 16 84 00 d1 ea 00 00 00 00 00 00
0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00
```
#### Reference output
Reference output (in case of `icmp6` sniffing) of the sniffer should not contain anything.

Reference output (in case of `mld` sniffing) of the sniffer should contain following information:

- `src MAC: 00:15:5D:A0:4D:73` - source MAC address
- `dst MAC: 33:33:00:00:00:16` - destination MAC address
- `src IP: fe80::215:5dff:fea0:4d73` - source IP address
- `dst IP: ff02::16` - destination IP address
- `frame length: 78 bytes` - frame length

Additionally, sniffer should print the packet timestamp, hexdump and ascii dumps.

#### Sniffer output
Following output was produced by the sniffer (`mld` sniffing):
```
timestamp: 2024-04-21 22:16:05.598+00:00
src MAC: 00:15:5D:A0:4D:73
dst MAC: 33:33:00:00:00:16
frame length: 78 bytes
src IP: fe80::215:5dff:fea0:4d73
dst IP: ff02::16

0x0000:  33 33 00 00 00 16 00 15 5D A0 4D 73 86 DD 60 00  33......].Ms..`.
0x0010:  00 00 00 18 3A 01 FE 80 00 00 00 00 00 00 02 15  ....:...........
0x0020:  5D FF FE A0 4D 73 FF 02 00 00 00 00 00 00 00 00  ]...Ms..........
0x0030:  00 00 00 00 00 16 84 00 D1 EA 00 00 00 00 00 00  ................
0x0040:  00 00 00 00 00 00 00 00 00 00 00 00 00 00        ..............
```
In case of any other than `--mld` option, the sniffer did not print anything.

### NDP Test
#### Description
Test checks if sniffer is able to correctly recognise NDP packets, and do not recognise it as `icmp6` packets.
#### Sent packet
Following packet (dump from wireshark) was sent to the network:
```hexdump
0000   33 33 00 00 00 01 00 15 5d a0 4d 73 86 dd 60 00
0010   00 00 00 18 3a ff fe 80 00 00 00 00 00 00 02 15
0020   5d ff fe a0 4d 73 ff 02 00 00 00 00 00 00 00 00
0030   00 00 00 00 00 01 87 00 ce ff 00 00 00 00 00 00
0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00
```
#### Reference output
Reference output (in case of `icmp6` sniffing) of the sniffer should not contain anything.

Reference output (in case of `ndp` sniffing) of the sniffer should contain following information:
- `src MAC: 00:15:5D:A0:4D:73` - source MAC address
- `dst MAC: 33:33:00:00:00:01` - destination MAC address
- `src IP: fe80::215:5dff:fea0:4d73` - source IP address
- `dst IP: ff02::1` - destination IP address
- `frame length: 78 bytes` - frame length

Additionally, sniffer should print the packet timestamp, hexdump and ascii dumps.

#### Sniffer output
Following output was produced by the sniffer (`ndp` sniffing):
```
timestamp: 2024-04-21 22:50:18.078+00:00
src MAC: 00:15:5D:A0:4D:73
dst MAC: 33:33:00:00:00:01
frame length: 78 bytes
src IP: fe80::215:5dff:fea0:4d73
dst IP: ff02::1

0x0000:  33 33 00 00 00 01 00 15 5D A0 4D 73 86 DD 60 00  33......].Ms..`.
0x0010:  00 00 00 18 3A FF FE 80 00 00 00 00 00 00 02 15  ....:...........
0x0020:  5D FF FE A0 4D 73 FF 02 00 00 00 00 00 00 00 00  ]...Ms..........
0x0030:  00 00 00 00 00 01 87 00 CE FF 00 00 00 00 00 00  ................
0x0040:  00 00 00 00 00 00 00 00 00 00 00 00 00 00        ..............
```

In case of any other than `--ndp` option, the sniffer did not print anything.

### ICMPv6 Echo/Reply Test
#### Description
Test checks if sniffer is able to correctly recognise ICMPv6 Echo/Reply packets, and do not accept other types of ICMPv6 packets.
#### Sent packets
Following packets (dumps from wireshark) were sent to the network:
```hexdump
0000   33 33 00 00 00 16 00 15 5d a0 4d 73 86 dd 60 00
0010   00 00 00 18 3a 01 fe 80 00 00 00 00 00 00 02 15
0020   5d ff fe a0 4d 73 ff 02 00 00 00 00 00 00 00 00
0030   00 00 00 00 00 16 84 00 d1 ea 00 00 00 00 00 00
0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00
```
```hexdump
0000   33 33 00 00 00 01 00 15 5d a0 4d 73 86 dd 60 00
0010   00 00 00 18 3a ff fe 80 00 00 00 00 00 00 02 15
0020   5d ff fe a0 4d 73 ff 02 00 00 00 00 00 00 00 00
0030   00 00 00 00 00 01 87 00 ce ff 00 00 00 00 00 00
0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00
```
```hexdump
0000   33 33 00 00 00 01 00 15 5d a0 4d 73 86 dd 60 00
0010   00 00 00 08 3a 40 fe 80 00 00 00 00 00 00 02 15
0020   5d ff fe a0 4d 73 ff 02 00 00 00 00 00 00 00 00
0030   00 00 00 00 00 01 80 00 d6 0f 00 00 00 00
```
#### Reference output
Reference output (in case of `icmp6` sniffing) of the sniffer should contain only last packet and following information:
- `src MAC: 00:15:5D:A0:4D:73` - source MAC address
- `dst MAC: 33:33:00:00:00:01` - destination MAC address
- `src IP: fe80::215:5dff:fea0:4d73` - source IP address
- `dst IP: ff02::1` - destination IP address
- `frame length: 62 bytes` - frame length

Additionally, sniffer should print the packet timestamp, hexdump and ascii dumps.

#### Sniffer output
Following output was produced by the sniffer (`icmp6` sniffing):
```
timestamp: 2024-04-21 23:08:05.688+00:00
src MAC: 00:15:5D:A0:4D:73
dst MAC: 33:33:00:00:00:01
frame length: 62 bytes
src IP: fe80::215:5dff:fea0:4d73
dst IP: ff02::1

0x0000:  33 33 00 00 00 01 00 15 5D A0 4D 73 86 DD 60 00  33......].Ms..`.
0x0010:  00 00 00 08 3A 40 FE 80 00 00 00 00 00 00 02 15  ....:@..........
0x0020:  5D FF FE A0 4D 73 FF 02 00 00 00 00 00 00 00 00  ]...Ms..........
0x0030:  00 00 00 00 00 01 80 00 D6 0F 00 00 00 00        ..............
```
Nothing else was printed.

## Bibliography
[RFC792] POSTEL, J. _Internet Control Message Protocol_ [online]. 1981. DOI: 10.17487/RFC0792. Available at: https://datatracker.ietf.org/doc/html/rfc0792

[RFC826] PLUMMER, D. _Ethernet address resolution Protocol: or converting network protocol addresses to 48.bit ethernet address for transmission on ethernet hardware_ [online]. 1982. DOI: 10.17487/RFC826. Available at: https://datatracker.ietf.org/doc/html/rfc0826

[RFC3339] KLYNE, Graham and Chris NEWMAN. _Date and time on the internet: timestamps_ [online]. 2002. DOI: 10.17487/RFC3339. Available at: https://datatracker.ietf.org/doc/html/rfc3339

[RFC4443] CONTA, A. and S. DEERING. _Internet Control Message Protocol (ICMPV6) for the Internet Protocol Version 6 (IPV6) specification_ [online]. 2006. DOI: 10.17487/RFC4443. Available at: https://datatracker.ietf.org/doc/html/rfc4443

[RFC5952] KAWAMURA, Seiichi and Masanobu KAWASHIMA. _A recommendation for IPV6 address text representation_ [online]. 2010. DOI: 10.17487/RFC5952. Available at: https://datatracker.ietf.org/doc/html/rfc5952
