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
    
    private string TimeStamp => _rawCapture.Timeval.Date.ToString("yyyy-MM-dd HH:mm:ss.fffzzz");
    
    private string? FormatMac(string? unformattedMac)
    {
        if (unformattedMac == null)
        {
            return null;
        }
        return string.Join(":", Enumerable.Range(0, 6)
            .Select(i => unformattedMac.Substring(i * 2, 2)));
    }
    
    private static string HexDump(byte[] data)
    {
        // offset : bytes : ascii
        var hex = new StringBuilder();
        var ascii = new StringBuilder();
        var offset = 0;
        for (int i = 0; i < data.Length; i++)
        {
            if (i % 16 == 0)
            {
                hex.Append($"0x{offset:X4}: ");
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
                hex.Append(ascii);
                hex.Append("\n");
                ascii.Clear();
            }
        }
        if (ascii.Length > 0)
        {
            hex.Append(new string(' ', 3 * (16 - ascii.Length)));
            hex.Append(ascii);
            hex.Append("\n");
        }
        return hex.ToString();
    }
}