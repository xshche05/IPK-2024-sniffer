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
        for (int i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
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
        // todo validate options
    }
    
    public bool IsCapAll()
    {
        return !Tcp && !Udp && !Icmp4 && !Icmp6 && !Arp && !Ndp && !Igmp && !Mld;
    }
}