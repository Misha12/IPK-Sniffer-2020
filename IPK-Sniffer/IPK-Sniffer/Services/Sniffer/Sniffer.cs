using PacketDotNet;
using PacketDotNet.Tcp;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPK_Sniffer.Services.Sniffer
{
    // TODO: Komentáře.
    public static class Sniffer
    {
        private static LibPcapLiveDevice Device { get; set; }
        private static Options Options { get; set; }

        private static uint PacketCounter { get; set; }

        public static void Process(Options options)
        {
            Options = options;
            SetDevice(options.Interface);

            try
            {
                Device.OnPacketArrival += Device_OnPacketArrival;
                
                Device.Open(DeviceMode.Promiscuous);
                Device.Capture();
            }
            catch (PcapException ex)
            {
                Console.WriteLine(ex.ToString());
                // TODO: catch exceptions from pcap library.
            }
        }

        private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            // TODO: Doplnit odkazy na použití sharpcap knihovny.
            if (e.Packet.LinkLayerType != LinkLayers.Ethernet)
                return;

            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data) as EthernetPacket;

            if (!IsSupportedPacket(packet))
                return;

            if (EthernetPacketPrinter.PrintPacket(packet) && ++PacketCounter == Options.PacketCountLimit)
            {
                Dispose();
                Environment.Exit(AppCodes.Success);
            }
        }

        private static void SetDevice(string name)
        {
            var devices = CaptureDeviceList.New();
            var device = devices.FirstOrDefault(o => o.Name == name);

            if (device == null)
            {
                Console.Error.WriteLine($"Bylo zadáno neplatné rozhraní.\nNápovědu vypíšete parametrem --help.");
                Environment.Exit(AppCodes.InvalidInterface);
            }

            Device = device as LibPcapLiveDevice;
        }

        public static void Dispose()
        {
            if (Device == null) return;

            if (Device.Opened)
                Device.Close();
        }

        private static bool IsSupportedPacket(EthernetPacket packet)
        {
            if (!packet.HasPayloadPacket || !(packet.PayloadPacket is IPPacket ipPacket))
                return false;

            if (Options.OnlyTCP && ipPacket.Protocol != ProtocolType.Tcp)
                return false;

            if (Options.OnlyUDP && ipPacket.Protocol != ProtocolType.Udp)
                return false;

            if (Options.Port != null
                && ipPacket.PayloadPacket is TransportPacket transportPacket
                && transportPacket.SourcePort != Options.Port.Value
                && transportPacket.DestinationPort != Options.Port.Value)
                return false;

            return true;
        }
    }
}
