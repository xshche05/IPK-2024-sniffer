using SharpPcap;
using SharpPcap.LibPcap;

namespace PacketSniffer;
public static class Program
{
    private static Options _options = null!;
    public static Options Options => _options;
    public static LibPcapLiveDevice Interface { get; private set; } = null!;
    public static void Main(string[] args)
    {
        // setup line breaks for console output
        Console.Error.NewLine = "\n";
        Console.Out.NewLine = "\n";
        
        _options = Options.Parse(args);
        _options.Validate();

        if (_options.Interface is null)
        {
            // Print all available interfaces
            var devices = CaptureDeviceList.Instance.ToList();
            foreach (var device in devices)
            {
                Console.WriteLine($"{device.Name} - {device.Description}");
            }
            // Exit the program
            Environment.Exit(0);
        }
        
        // Find the interface by name
        var interfaceDevice = CaptureDeviceList.Instance.FirstOrDefault(d => d?.Name == _options.Interface, null);
        Interface = interfaceDevice as LibPcapLiveDevice ?? throw new ApplicationException("Interface not found, invalid name!");
    }
}