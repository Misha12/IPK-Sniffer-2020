using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Linq;

namespace IPK_Sniffer.Services.Sniffer
{
    /// <summary>
    /// Hlavní třída pro zachytávání packetů.
    /// </summary>
    public static class Sniffer
    {
        /// <summary>
        /// Aktuální rozhraní, které poslouchá.
        /// </summary>
        private static LibPcapLiveDevice Device { get; set; }

        /// <summary>
        /// Konfigurace apliakce.
        /// </summary>
        private static Options Options { get; set; }

        /// <summary>
        /// Počítadlo zachycených packetů.
        /// </summary>
        private static uint PacketCounter { get; set; }

        public static void Process(Options options)
        {
            Options = options;
            SetDevice(options.Interface);

            Device.OnPacketArrival += Device_OnPacketArrival;

            Device.Open(DeviceMode.Promiscuous, 100);
            Device.Capture();
        }

        /// <summary>
        /// Metoda, která je volána při zachycení události.
        /// </summary>
        private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            if (e.Packet.LinkLayerType != LinkLayers.Ethernet)
                return;

            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data) as EthernetPacket;

            if (!IsSupportedPacket(packet))
                return;

            var ipPacket = packet.PayloadPacket as IPPacket;

            bool success = false;
            if (ipPacket.Protocol == ProtocolType.Tcp || ipPacket.Protocol == ProtocolType.Udp)
                success = Printer.Printer.PrintTcpAndUdpPackets(packet);
            else if (ipPacket.Protocol == ProtocolType.Icmp || ipPacket.Protocol == ProtocolType.IcmpV6)
                success = Printer.Printer.PrintICMPPackets(packet);

            if (success && ++PacketCounter == Options.PacketCountLimit)
            {
                DisposeDevice();
                Environment.Exit(AppCodes.Success);
            }
        }

        private static void SetDevice(string name)
        {
            var device = CaptureDeviceList.New().FirstOrDefault(o => o.Name == name);

            if (device == null)
            {
                Console.Error.WriteLine($"Bylo zadáno neplatné rozhraní.\nNápovědu vypíšete parametrem --help.");
                Environment.Exit(AppCodes.InvalidInterface);
            }

            Device = device as LibPcapLiveDevice;
        }

        public static void DisposeDevice()
        {
            if (Device == null) return;

            if (Device.Opened)
                Device.Close();
        }

        private static bool IsSupportedPacket(EthernetPacket packet)
        {
            if (!packet.HasPayloadPacket || !(packet.PayloadPacket is IPPacket ipPacket))
                return false;

            var protocol = ipPacket.Protocol;
            if (protocol != ProtocolType.Tcp && protocol != ProtocolType.Udp
                && protocol != ProtocolType.Icmp && protocol != ProtocolType.IcmpV6)
                return false;

            if (Options.Port != null
                && ipPacket.PayloadPacket is TransportPacket transportPacket
                && transportPacket.SourcePort != Options.Port.Value
                && transportPacket.DestinationPort != Options.Port.Value)
                return false;

            if (!Options.OnlyICMP && !Options.OnlyTCP && !Options.OnlyUDP)
                return true;

            if (Options.OnlyTCP && ipPacket.Protocol == ProtocolType.Tcp)
                return true;

            if (Options.OnlyUDP && ipPacket.Protocol == ProtocolType.Udp)
                return true;

            if (Options.OnlyICMP && (ipPacket.Protocol == ProtocolType.Icmp || ipPacket.Protocol == ProtocolType.IcmpV6))
                return true;

            return false;
        }
    }
}
