﻿using PacketDotNet;
using System;

namespace IPK_Sniffer.Services.Sniffer.Printer
{
    public static class Printer
    {
        /// <summary>
        /// Výpis TCP a UDP packetů.
        /// </summary>
        public static bool PrintTcpAndUdpPackets(EthernetPacket packet)
        {
            if (!(packet.PayloadPacket is IPPacket networkLayer) || !(networkLayer.PayloadPacket is TransportPacket transportLayer))
                return false;

            var source = PrinterHelper.TryGetHostname(networkLayer.SourceAddress);
            var destination = PrinterHelper.TryGetHostname(networkLayer.DestinationAddress);

            Console.WriteLine($"{DateTime.Now.TimeOfDay} {source} : {transportLayer.SourcePort} > {destination} : {transportLayer.DestinationPort}\n");
            PrinterHelper.PrintPacketData(packet);
            Console.WriteLine();

            return true;
        }

        /// <summary>
        /// Výpis ICMP packetů.
        /// </summary>
        public static bool PrintICMPPackets(EthernetPacket packet)
        {
            if (!(packet.PayloadPacket is IPPacket networkLayer))
                return false;

            if (networkLayer.PayloadPacket is IcmpV4Packet || networkLayer.PayloadPacket is IcmpV6Packet)
            {
                var source = PrinterHelper.TryGetHostname(networkLayer.SourceAddress);
                var destination = PrinterHelper.TryGetHostname(networkLayer.DestinationAddress);

                Console.WriteLine($"{DateTime.Now.TimeOfDay} (ICMP) {source} > {destination}\n");
                PrinterHelper.PrintPacketData(packet);
                Console.WriteLine();

                return true;
            }

            return false;
        }
    }
}
