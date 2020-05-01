using PacketDotNet;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace IPK_Sniffer.Services.Sniffer
{
    public static class EthernetPacketPrinter
    {
        public static bool PrintPacket(EthernetPacket packet)
        {
            if (!(packet.PayloadPacket is IPPacket networkLayer) || !(networkLayer.PayloadPacket is TransportPacket transportLayer))
                return false;

            var source = networkLayer.SourceAddress;
            var destination = networkLayer.DestinationAddress;

            Console.WriteLine($"{DateTime.Now.TimeOfDay} {TryGetHostname(source)} : {transportLayer.SourcePort} > {TryGetHostname(destination)} : {transportLayer.DestinationPort}");

            Print(packet);
            Console.WriteLine();
            return true;
        }

        /// <summary>
        /// Získání doménového názvu z IP adresy.
        /// </summary>
        /// <remarks>
        /// Zdroj: IPK 1. Projekt HTTP Server/DNS Resolver (Halabica Michal)
        /// Soubor: src/Resolver/Services/DnsResolveService.cs
        /// </remarks>
        private static string TryGetHostname(IPAddress address)
        {
            var task = Task.Run(() =>
            {
                try
                {
                    var noDnsAddresses = new[]
                    {
                        IPAddress.Any,
                        IPAddress.IPv6Any,
                        IPAddress.Broadcast,
                        IPAddress.None
                    };

                    if (noDnsAddresses.Any(o => o.Equals(address)))
                        return address.ToString();

                    var dns = Dns.GetHostEntry(address);
                    return string.IsNullOrEmpty(dns.HostName) ? address.ToString() : dns.HostName;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
                {
                    return address.ToString();
                }
            });

            return task.Wait(800) ? task.Result : address.ToString();
        }

        private static void Print(EthernetPacket packet)
        {
            var buffer = new StringBuilder();
            var ascii = new StringBuilder();

            // Pocitame od 1, ale indexace se provadi od 0. To kvuli tomu, aby se spravne zarovnala data s odradkovanim ve vypisu.
            for (int i = 1; i <= packet.BytesSegment.Bytes.Length; i++)
            {
                var realIndex = i - 1;

                var byteData = packet.BytesSegment.Bytes[realIndex];
                buffer.Append(byteData.ToString("x").PadLeft(2, '0')).Append(' ');

                /// <see cref="https://en.wikipedia.org/wiki/ASCII#Printable_characters"/>
                if (byteData >= 0x21 && byteData < 0x7e)
                    ascii.Append(Encoding.ASCII.GetString(new[] { byteData }));
                else
                    ascii.Append('.');

                // Každých 16 bajtů odřádkujeme.
                if (i % 16 == 0)
                {
                    PrintLine(buffer, ascii, i, false);
                }
                else
                {
                    if (i % 8 == 0)
                    {
                        buffer.Append(' ');
                        ascii.Append(' ');
                    }
                }
            }

            PrintLine(buffer, ascii, packet.BytesSegment.Bytes.Length, true);
        }

        private static void PrintLine(StringBuilder builder, StringBuilder ascii, int processedBytes, bool last)
        {
            int processedBytesCount = (processedBytes - (last ? 0 : 16)) / 16;
            /// <see cref="https://stackoverflow.com/a/11866297">
            Console.WriteLine("0x{0:X3}0: {1} {2}", processedBytesCount, builder.ToString().PadRight(49, ' '), ascii.ToString());

            builder.Clear();
            ascii.Clear();
        }
    }
}
