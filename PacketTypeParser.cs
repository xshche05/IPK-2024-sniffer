using PacketDotNet;

namespace PacketSniffer;

public static class PacketTypeParser
{   
    /* Gets packet type if selected by options
     * in case of unknown packet type or not selected by options returns PacketType.Ignore
     */
    public static PacketType GetPacketType(Packet packet)
    {
        // try to get tcp
        var tcpPacket = packet.Extract<TcpPacket>();
        if (tcpPacket != null && (Program.Options.Tcp || Program.Options.IsCapAll()))
        {
            if (Program.Options.Port != 0 || Program.Options.PortSource != 0 || Program.Options.PortDestination != 0)
            {
                var srcPort = tcpPacket.SourcePort;
                var dstPort = tcpPacket.DestinationPort;
                if (Program.Options.Port != 0 && (srcPort == Program.Options.Port || dstPort == Program.Options.Port))
                {
                    return PacketType.Tcp;
                }
                if (Program.Options.PortSource != 0 && srcPort == Program.Options.PortSource)
                {
                    return PacketType.Tcp;
                }
                if (Program.Options.PortDestination != 0 && dstPort == Program.Options.PortDestination)
                {
                    return PacketType.Tcp;
                }
                return PacketType.Ignore;
            }
            return PacketType.Tcp;
        }
        // try to get udp
        var udpPacket = packet.Extract<UdpPacket>();
        if (udpPacket != null && (Program.Options.Udp || Program.Options.IsCapAll()))
        {
            if (Program.Options.Port != 0 || Program.Options.PortSource != 0 || Program.Options.PortDestination != 0)
            {
                var srcPort = udpPacket.SourcePort;
                var dstPort = udpPacket.DestinationPort;
                if (Program.Options.Port != 0 && (srcPort == Program.Options.Port || dstPort == Program.Options.Port))
                {
                    return PacketType.Udp;
                }
                if (Program.Options.PortSource != 0 && srcPort == Program.Options.PortSource)
                {
                    return PacketType.Udp;
                }
                if (Program.Options.PortDestination != 0 && dstPort == Program.Options.PortDestination)
                {
                    return PacketType.Udp;
                }
                return PacketType.Ignore;
            }
            return PacketType.Udp;
        }
        // try to get arp
        var arpPacket = packet.Extract<ArpPacket>();
        if (arpPacket != null && (Program.Options.Arp || Program.Options.IsCapAll()))
        {
            return PacketType.Arp;
        }
        // try to get icmp4
        var icmpV4Packet = packet.Extract<IcmpV4Packet>();
        if (icmpV4Packet != null && (Program.Options.Icmp4 || Program.Options.IsCapAll()))
        {
            return PacketType.Icmp4;
        }
        // try to get icmp6 echo request/reply
        var icmpV6Packet = packet.Extract<IcmpV6Packet>();
        if (icmpV6Packet != null && (Program.Options.Icmp6 || Program.Options.IsCapAll()))
        {
            if (icmpV6Packet.Type == IcmpV6Type.EchoReply
                || icmpV6Packet.Type == IcmpV6Type.EchoRequest)
            {
                return PacketType.Icmp6;
            }
        }
        // if mld is selected, try to get mld if present
        if (icmpV6Packet != null && (Program.Options.Mld || Program.Options.IsCapAll())) 
        {
            var type = icmpV6Packet.Type;
            // check if type is one of the MLD types
            if (type == IcmpV6Type.MulticastListenerQuery
                || type == IcmpV6Type.MulticastListenerReport
                || type == IcmpV6Type.MulticastListenerDone
                || type == IcmpV6Type.Version2MulticastListenerReport)
            {
                return PacketType.Mld;
            }
        }
        // if ndp is selected, try to get ndp if presentq
        if (icmpV6Packet != null && (Program.Options.Ndp || Program.Options.IsCapAll()))
        {
            var type = icmpV6Packet.Type;
            // check if type is one of the NDP types
            if (type == IcmpV6Type.RouterSolicitation
                || type == IcmpV6Type.RouterAdvertisement
                || type == IcmpV6Type.NeighborSolicitation
                || type == IcmpV6Type.NeighborAdvertisement
                || type == IcmpV6Type.RedirectMessage)
            {
                return PacketType.Ndp;
            }
        }
        // try to get igmp
        var igmpPacket = packet.Extract<IgmpPacket>();
        if (igmpPacket != null && (Program.Options.Igmp || Program.Options.IsCapAll()))
        {
            return PacketType.Igmp;
        }
        return PacketType.Ignore;
    }
}