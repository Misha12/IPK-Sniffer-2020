using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;

namespace IPK_Sniffer
{
    /// <summary>
    /// Třída pro zpracovaná data příkazové řádky.
    /// </summary>
    public class Options
    {
        [Option('i', HelpText = "Rozhraní, na kterém má aplikace naslouchat.", Required = true)]
        public string Interface { get; set; }

        [Option('p', HelpText = "Omezení filtrování paketů na zadané porty.", Required = false, Separator = ',')]
        public IEnumerable<int> Ports { get; set; }

        [Option('t', "tcp", HelpText = "Omezení filtrování paketů pouze na TCP protokol.")]
        public bool OnlyTCP { get; set; }

        [Option('u', "udp", HelpText = "Omezení filtrování paketů pouze na UDP protokol.")]
        public bool OnlyUDP { get; set; }

        [Option("icmp", HelpText = "Omezení filtrování packetů pouze na ICMP protokol.")]
        public bool OnlyICMP { get; set; }

        [Option('n', HelpText = "Očekávaný počet packetů, které má aplikace zachytit.", Default = 1)]
        public int PacketCountLimit { get; set; } = 1;

        public void Validate()
        {
            if (Ports != null && Ports.Any())
            {
                foreach (var port in Ports)
                {
                    if(port < 0 || port > ushort.MaxValue)
                    {
                        Console.Error.WriteLine($"Port {port} je mimo rozsah platných portů.");
                        Environment.Exit(AppCodes.InvalidInputPort);
                    }
                }
            }
        }
    }
}
