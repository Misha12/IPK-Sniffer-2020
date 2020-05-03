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
        /// <summary>
        /// DNS Cache.
        /// </summary>
        private static Dictionary<string, string> DnsCache { get; set; } = new Dictionary<string, string>()
        {
            { IPAddress.Any.ToString(), IPAddress.Any.ToString() },
            { IPAddress.IPv6Any.ToString(), IPAddress.IPv6Any.ToString() },
            { IPAddress.Broadcast.ToString(), IPAddress.Broadcast.ToString() }
        };

        /// <summary>
        /// Získání doménového názvu z IP adresy.
        /// </summary>
        /// <remarks>
        /// Čerpáno z:
        /// IPK 1. Projekt HTTP Server/DNS Resolver (Halabica Michal (xhalab00))
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

                    if(!DnsCache.ContainsKey(addr))
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
            var hexa = new StringBuilder();
            var ascii = new StringBuilder();

            // Pocitame od 1, ale indexace se provadi od 0. To kvuli tomu, aby se spravne zarovnala data s odradkovanim ve vypisu.
            for (int i = 1; i <= packet.BytesSegment.Bytes.Length; i++)
            {
                var realIndex = i - 1;

                var byteData = packet.BytesSegment.Bytes[realIndex];
                hexa.Append(byteData.ToString("x").PadLeft(2, '0')).Append(' ');

                /// <see cref="https://en.wikipedia.org/wiki/ASCII#Printable_characters"/>
                if (byteData >= 0x21 && byteData < 0x7e)
                    ascii.Append(Encoding.ASCII.GetString(new[] { byteData }));
                else
                    ascii.Append('.');

                // Každých 16 bajtů odřádkujeme.
                if (i % 16 == 0)
                {
                    PrintLine(hexa, ascii, i, false);
                }
                else
                {
                    if (i % 8 == 0)
                    {
                        hexa.Append(' ');
                        ascii.Append(' ');
                    }
                }
            }

            PrintLine(hexa, ascii, packet.BytesSegment.Bytes.Length, true);
        }

        /// <summary>
        /// Výpis jednoho řádku dat.
        /// </summary>
        /// <param name="hexa">Obsah množiny dat packetu v hexadecimálním formátu.</param>
        /// <param name="ascii">Obsah množiny dat v packetu v ASCII.</param>
        /// <param name="processedBytes">Počet vypsaných bajtů</param>
        /// <param name="lastLine">Příznak, že se jedná o poslední řádek. Slouží ke správnému formátování.</param>
        private static void PrintLine(StringBuilder hexa, StringBuilder ascii, int processedBytes, bool lastLine)
        {
            int processedBytesCount = (processedBytes - (lastLine ? 0 : 16)) / 16;
            /// <see cref="https://stackoverflow.com/a/11866297">
            Console.WriteLine("0x{0:X3}0: {1} {2}", processedBytesCount, hexa.ToString().PadRight(49, ' '), ascii.ToString());

            hexa.Clear();
            ascii.Clear();
        }
    }
}
