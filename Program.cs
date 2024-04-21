namespace PacketSniffer;
public static class Program
{
    private static Options _options = Options.Parse(new string[0]);
    public static Options Options => _options;
    public static void Main(string[] args)
    {
        _options = Options.Parse(args);
        _options.Validate();
    }
}