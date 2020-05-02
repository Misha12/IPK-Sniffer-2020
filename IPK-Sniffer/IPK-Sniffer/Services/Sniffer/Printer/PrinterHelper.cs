using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace IPK_Sniffer.Services.Sniffer.Printer
{
    public static class PrinterHelper
    {
        private static Dictionary<string, string> DnsCache { get; set; } = new Dictionary<string, string>()
        {
            { IPAddress.Any.ToString(), IPAddress.Any.ToString() },
            { IPAddress.IPv6Any.ToString(), IPAddress.Any.ToString() },
            { IPAddress.Broadcast.ToString(), IPAddress.Broadcast.ToString() }
        };

        /// <summary>
        /// Získání doménového názvu z IP adresy.
        /// </summary>
        /// <remarks>
        /// Zdroj: IPK 1. Projekt HTTP Server/DNS Resolver (Halabica Michal (xhalab00))
        /// Soubor: src/Resolver/Services/DnsResolveService.cs
        /// </remarks>
        public static string TryGetHostname(IPAddress address)
        {
            var task = Task.Run(() =>
            {
                try
                {
                    var addr = address.ToString();

                    if (DnsCache.ContainsKey(addr))
                        return DnsCache[addr];

                    var dns = Dns.GetHostEntry(address);

                    if (string.IsNullOrEmpty(dns.HostName))
                        return addr;

                    DnsCache.Add(addr, dns.HostName);
                    return dns.HostName;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.HostNotFound)
                {
                    return address.ToString();
                }
            });

            return task.Wait(300) ? task.Result : address.ToString();
        }

        /// <summary>
        /// Vypis obsahu packetu.
        /// </summary>
        public static void PrintPacketData(EthernetPacket packet)
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
