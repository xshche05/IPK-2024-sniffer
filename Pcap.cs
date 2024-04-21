using SharpPcap;

namespace PacketSniffer;

public static class Pcap
{
    private static readonly object CaptureLock = new ();
    private static int _numOfCapturedPackets = 0;
    private static readonly Semaphore StopSemaphore = new (0, 1);
    
    public static void Capture()
    {
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            Program.Interface.StopCapture();
            Program.Interface.Close();
            StopSemaphore.Release();
        };
        Program.Interface.Open(DeviceModes.Promiscuous);
        Program.Interface.OnPacketArrival += OnPacketArrival;
        Program.Interface.StartCapture();
        StopSemaphore.WaitOne();
    }
    
    private static void OnPacketArrival(object _, PacketCapture e)
    {
        lock (CaptureLock)
        {
            // if the number of captured packets is equal or more than number of packets to capture, stop capturing
            if (!(_numOfCapturedPackets < Program.Options.Num))
            {
                Program.Interface.StopCapture();
                Program.Interface.Close();
                StopSemaphore.Release();
                return;
            }
            // parse the packet
            
            // print the packet
            
            // if printed, increment the number of captured packets
        }
    }
}