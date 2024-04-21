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
}