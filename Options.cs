namespace PacketSniffer;

public class Options
{
    public string? Interface { get; set; } = null;
    public bool Tcp { get; set; }
    public bool Udp { get; set; }
    public int Port { get; set; } = 0;
    public int PortDestination { get; set; } = 0;
    public int PortSource { get; set; } = 0;
    public bool Icmp4 { get; set; }
    public bool Icmp6 { get; set; }
    public bool Arp { get; set; }
    public bool Ndp { get; set; }
    public bool Igmp { get; set; }
    public bool Mld { get; set; }
    public int Num { get; set; } = 1;
    private string[] _args;
    
    private Options(string[] args)
    {
        _args = args;
    }

    public static Options Parse(string[] args)
    {
        var options = new Options(args);
        // todo parse options
        return options;
    }
    
    public void Validate()
    {
        // todo validate options
    }
    
    public bool IsCapAll()
    {
        return !Tcp && !Udp && !Icmp4 && !Icmp6 && !Arp && !Ndp && !Igmp && !Mld;
    }
}