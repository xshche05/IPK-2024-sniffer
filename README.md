# ipk-project2-sniffer

An IPK course project, network packet sniffer

## Tests

### MLD Tests
Following packet was sent to the network:
```hexdump
33 33 00 00 00 16 00 15 5d a0 4d 73 86 dd 60 00
00 00 00 18 3a 01 fe 80 00 00 00 00 00 00 02 15
5d ff fe a0 4d 73 ff 02 00 00 00 00 00 00 00 00
00 00 00 00 00 16 83 00 d2 ea 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00
```
Reference output of the sniffer should contain:

`src MAC: 00:15:5D:A0:4D:73` - source MAC address \
`dst MAC: 33:33:00:00:00:16` - destination MAC address \
`frame length: 78 bytes` - frame length \
`src IP: fe80::215:5dff:fea0:4d73` - source IP address \
`dst IP: ff02::16` - destination IP address \

## Bibliography
[RFC792] POSTEL, J. _Internet Control Message Protocol_ [online]. 1981. DOI: 10.17487/RFC0792. Available at: https://datatracker.ietf.org/doc/html/rfc0792

[RFC826] PLUMMER, D. _Ethernet address resolution Protocol: or converting network protocol addresses to 48.bit ethernet address for transmission on ethernet hardware_ [online]. 1982. DOI: 10.17487/RFC826. Available at: https://datatracker.ietf.org/doc/html/rfc0826

[RFC3339] KLYNE, Graham and Chris NEWMAN. _Date and time on the internet: timestamps_ [online]. 2002. DOI: 10.17487/RFC3339. Available at: https://datatracker.ietf.org/doc/html/rfc3339

[RFC4443] CONTA, A. and S. DEERING. _Internet Control Message Protocol (ICMPV6) for the Internet Protocol Version 6 (IPV6) specification_ [online]. 2006. DOI: 10.17487/RFC4443. Available at: https://datatracker.ietf.org/doc/html/rfc4443

[RFC5952] KAWAMURA, Seiichi and Masanobu KAWASHIMA. _A recommendation for IPV6 address text representation_ [online]. 2010. DOI: 10.17487/RFC5952. Available at: https://datatracker.ietf.org/doc/html/rfc5952
