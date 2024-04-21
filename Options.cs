namespace PacketSniffer;

public class Options
{
    private readonly string _helpMessage =
        "Usage: ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n" +
        "   -i or --interface: Specify interface to sniff. Without value, list active interfaces.\n" +
        "   -t or --tcp: Display TCP segments.\n" +
        "   -u or --udp: Display UDP datagrams.\n" +
        "   -p: Filter TCP/UDP by port number.\n" +
        "   --port-destination: Filter TCP/UDP by destination port.\n" +
        "   --port-source: Filter TCP/UDP by source port.\n" +
        "   --icmp4: Display only ICMPv4 packets.\n" +
        "   --icmp6: Display only ICMPv6 echo request/response.\n" +
        "   --arp: Display only ARP frames.\n" +
        "   --ndp: Display only NDP packets (subset of ICMPv6).\n" +
        "   --igmp: Display only IGMP packets.\n" +
        "   --mld: Display only MLD packets (subset of ICMPv6).\n" +
        "   -n 10: Specify number of packets to display (default: 1).\n" +
        "   All protocols considered unless explicitly specified.";
    public string? Interface { get; private set; }
    public bool Tcp { get; private set; }
    public bool Udp { get; private set; }
    public int Port { get; private set; }
    public int PortDestination { get; private set; }
    public int PortSource { get; private set; }
    public bool Icmp4 { get; private set; }
    public bool Icmp6 { get; private set; }
    public bool Arp { get; private set; }
    public bool Ndp { get; private set; }
    public bool Igmp { get; private set; }
    public bool Mld { get; private set; }
    public int Num { get; private set; } = 1;
    private string[] _args;
    
    private Options(string[] args)
    {
        _args = args;
    }

    public static Options Parse(string[] args)
    {
        // Parse command line arguments
        var options = new Options(args);
        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "-h":
                case "--help":
                    Console.WriteLine(options._helpMessage);
                    Environment.Exit(0);
                    break;
                case "-i":
                case "--interface":
                    if (i + 1 >= args.Length)
                    {
                        options.Interface = null;
                    }
                    else
                    {
                        options.Interface = args[++i];   
                    }
                    break;
                case "-p":
                    try 
                    {
                        options.Port = int.Parse(args[++i]);
                    }
                    catch (Exception)
                    {
                        throw new ApplicationException("Invalid argument -p");
                    }
                    break;
                case "--port-source":
                    try 
                    {
                        options.PortSource = int.Parse(args[++i]);
                    }
                    catch (Exception)
                    {
                        throw new ApplicationException("Invalid argument --port-source");
                    }
                    break;
                case "--port-destination":
                    try 
                    {
                        options.PortDestination = int.Parse(args[++i]);
                    }
                    catch (Exception)
                    {
                        throw new ApplicationException("Invalid argument --port-destination");
                    }
                    break;
                case "--tcp":
                case "-t":
                    options.Tcp = true;
                    break;
                case "--udp":
                case "-u":
                    options.Udp = true;
                    break;
                case "--arp":
                    options.Arp = true;
                    break;
                case "--ndp":
                    options.Ndp = true;
                    break;
                case "--icmp4":
                    options.Icmp4 = true;
                    break;
                case "--icmp6":
                    options.Icmp6 = true;
                    break;
                case "--igmp":
                    options.Igmp = true;
                    break;
                case "--mld":
                    options.Mld = true;
                    break;
                case "-n":
                    try
                    {
                       options.Num = int.Parse(args[++i]); 
                    }
                    catch (Exception)
                    {
                        throw new ApplicationException("Invalid argument -n");
                    }
                    break;
                default:
                    throw new ApplicationException("Invalid argument: " + arg);
            }
        }
        return options;
    }
    
    public void Validate()
    {
        // If no interface is specified, no other options are allowed
        if (Interface == null && _args.Length != 1)
            throw new ApplicationException("not allowed options without interface specified");
        // port filter is not allowed with port source or port destination
        if (Port != 0 && (PortSource != 0 || PortDestination != 0))
            throw new ApplicationException("port filter with port and port source or port destination");
        // if port filter is specified, protocol udp or tcp must be specified
        if ((Port != 0 || PortSource != 0 || PortDestination != 0) && !Tcp && !Udp)
            throw new ApplicationException("port filter without TCP/UDP protocol");
    }
    
    public bool IsCapAll() // if no protocol is specified, capture all
    {
        return !Tcp && !Udp && !Icmp4 && !Icmp6 && !Arp && !Ndp && !Igmp && !Mld;
    }
}