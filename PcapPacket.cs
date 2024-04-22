using System.Text;
using PacketDotNet;
using SharpPcap;

namespace PacketSniffer;

public class PcapPacket
{
    private readonly PacketType _packetType;
    private readonly Packet _packetData;
    private readonly RawCapture _rawCapture;
    
    public PcapPacket(RawCapture packet)
    {
        _rawCapture = packet;
        _packetData = Packet.ParsePacket(packet.LinkLayerType, packet.Data);
        _packetType = PacketTypeParser.GetPacketType(_packetData);
    }

    public bool Print()
    {
        if (_packetType == PacketType.Ignore)
        {
            return false; // Packed was ignored
        }
        Console.WriteLine($"timestamp: {TimeStamp}");
        PrintEthernetOrLinuxSll();
        if (SrcMac != null) // Print only if presented
        {
            Console.WriteLine($"src MAC: {SrcMac}");
        }
        if (DstMac != null)
        {
            Console.WriteLine($"dst MAC: {DstMac}");
        }
        Console.WriteLine($"frame length: {_rawCapture.PacketLength} bytes");
        PrintIpVersion();
        if (SrcIp != null)
        {
            Console.WriteLine($"src IP: {SrcIp}");
        }
        if (DstIp != null)
        {
            Console.WriteLine($"dst IP: {DstIp}");
        }
        Console.WriteLine($"{PacketTypeString}:");
        if (SrcPort != null)
        {
            Console.WriteLine($"src port: {SrcPort}");
        }
        if (DstPort != null)
        {
            Console.WriteLine($"dst port: {DstPort}");
        }
        Console.WriteLine($"\n{HexDump}\n\n");
        return true; // Packet was printed
    }
    
    private void PrintEthernetOrLinuxSll()
    {
        var ethernetPacket = _packetData.Extract<EthernetPacket>();
        if (ethernetPacket != null)
        {
            Console.WriteLine("Ethernet II: ");
            return;
        }
        var linuxSllPacket = _packetData.Extract<LinuxSllPacket>();
        if (linuxSllPacket != null)
        {
            Console.WriteLine("Linux Cooked Capture: ");
        }
    }
    
    private void PrintIpVersion()
    {
        var ipPacket = _packetData.Extract<IPPacket>();
        if (ipPacket != null)
        {
            Console.WriteLine($"Internet Protocol Version {(int)ipPacket.Version}:");
        }
    }
    
    private string TimeStamp => _rawCapture.Timeval.Date.ToString("yyyy-MM-dd HH:mm:ss.fffzzz");
    private string HexDump => GetHexDump(_rawCapture.Data);
    public string? SrcMac
    {
        get
        {
            // ScrMac is extracted from EthernetPacket or LinuxSllPacket
            var ethernetPacket = _packetData.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                return FormatMac(ethernetPacket.SourceHardwareAddress.ToString());
            }
            var linuxSllPacket = _packetData.Extract<LinuxSllPacket>();
            if (linuxSllPacket != null)
            {
                var mac = BitConverter.ToString(linuxSllPacket.LinkLayerAddress, 0);
                return FormatMac(mac.Replace("-", null));
            }
            return null;
        }
    }
    public string? DstMac
    {
        get
        {
            // DstMac is extracted from EthernetPacket
            var ethernetPacket = _packetData.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                return FormatMac(ethernetPacket.DestinationHardwareAddress.ToString());
            }
            return null;
        }
    }
    public string? SrcIp => _packetData.Extract<IPPacket>()?.SourceAddress.ToString();
    public string? DstIp => _packetData.Extract<IPPacket>()?.DestinationAddress.ToString();
    public int? SrcPort
    {
        get
        {
            // Port is extracted only in case of TCP or UDP
            TcpPacket? tcpPacket = _packetData.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                return tcpPacket.SourcePort;
            }
            UdpPacket? udpPacket = _packetData.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                return udpPacket.SourcePort;
            }
            return null;
        }
    }
    public int? DstPort
    {
        get
        {
            // Port is extracted only in case of TCP or UDP
            TcpPacket? tcpPacket = _packetData.Extract<TcpPacket>();
            if (tcpPacket != null)
            {
                return tcpPacket.DestinationPort;
            }
            UdpPacket? udpPacket = _packetData.Extract<UdpPacket>();
            if (udpPacket != null)
            {
                return udpPacket.DestinationPort;
            }
            return null;
        }
    }
    
    // Format MAC address from 001122334455 to 00:11:22:33:44:55
    private string? FormatMac(string? unformattedMac)
    {
        if (unformattedMac == null)
        {
            return null;
        }
        return string.Join(":", Enumerable.Range(0, 6)
            .Select(i => unformattedMac.Substring(i * 2, 2)));
    }
    private static string GetHexDump(byte[] data)
    {
        // offset : bytes : ascii
        var hex = new StringBuilder();
        var ascii = new StringBuilder();
        var offset = 0;
        for (int i = 0; i < data.Length; i++)
        {
            if (i % 16 == 0)
            {
                hex.Append($"0x{offset:X4}:  ");
                offset += 16;
            }
            hex.Append($"{data[i]:X2} ");
            if (data[i] < 32 || data[i] > 126)
            {
                ascii.Append(".");
            }
            else
            {
                ascii.Append((char)data[i]);
            }
            if ((i + 1) % 16 == 0)
            {
                hex.Append(" "+ascii);
                hex.Append("\n");
                ascii.Clear();
            }
        }
        if (ascii.Length > 0)
        {
            hex.Append(new string(' ', 3 * (16 - ascii.Length)));
            hex.Append(" "+ascii);
            hex.Append("\n");
        }
        return hex.ToString();
    }
    public string PacketTypeString
    {
        get
        {
            switch (_packetType)
            {
                case PacketType.Tcp:
                    return "Transmission Control Protocol";
                case PacketType.Udp:
                    return "User Datagram Protocol";
                case PacketType.Icmp4:
                    return "Internet Control Message Protocol v4";
                case PacketType.Icmp6:
                    return "Internet Control Message Protocol v6 Echo Request/Reply";
                case PacketType.Arp:
                    return "Address Resolution Protocol";
                case PacketType.Ndp:
                    return "Neighbor Discovery Protocol";
                case PacketType.Igmp:
                    return "Internet Group Management Protocol";
                case PacketType.Mld:
                    return "Multicast Listener Discovery Protocol";
                default:
                    return "Unknown or Ignored Packet Type";
            }
        }
    }
}