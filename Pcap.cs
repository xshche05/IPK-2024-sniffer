using SharpPcap;

namespace PacketSniffer;

public static class Pcap
{
    private static readonly object CaptureLock = new ();
    private static int _numOfCapturedPackets = 0;
    private static readonly Semaphore StopSemaphore = new (0, 1);
    
    public static void Capture()
    {
        // stop capturing on Ctrl+C
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
        StopSemaphore.WaitOne(); // lock the thread until capturing is stopped
    }
    
    // method called when packet is captured
    private static void OnPacketArrival(object _, PacketCapture e)
    {
        lock (CaptureLock) // lock to prevent same time access to shared resources
        {
            // if the number of captured packets is equal or more than number of packets to capture, stop capturing
            if (!(_numOfCapturedPackets < Program.Options.Num))
            {
                Program.Interface.StopCapture();
                Program.Interface.Close();
                StopSemaphore.Release(); // release the semaphore to unlock the thread and stop finish program
                return;
            }
            // parse the packet
            var rawPacket = e.GetPacket();
            PcapPacket packet = new PcapPacket(rawPacket);
            // print the packet
            // if printed, increment the number of captured packets
            if (packet.Print()) _numOfCapturedPackets++;
            if (!(_numOfCapturedPackets < Program.Options.Num))
            {
                Program.Interface.StopCapture();
                Program.Interface.Close();
                StopSemaphore.Release();
            }
        }
    }
}