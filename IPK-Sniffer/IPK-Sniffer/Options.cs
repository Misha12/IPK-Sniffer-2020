using CommandLine;

namespace IPK_Sniffer
{
    /// <summary>
    /// Třída pro zpracovaná data příkazové řádky.
    /// </summary>
    public class Options
    {
        [Option('i', HelpText = "Rozhraní, na kterém má aplikace naslouchat.", Required = true)]
        public string Interface { get; set; }

        [Option('p', HelpText = "Omezení filtrování paketů na zadané porty.")]
        public int? Port { get; set; }

        [Option('t', "tcp", HelpText = "Omezení filtrování paketů pouze na TCP spojení.")]
        public bool OnlyTCP { get; set; }

        [Option('u', "udp", HelpText = "Omezení filtrování paketů pouze na UDP spojení.")]
        public bool OnlyUDP { get; set; }

        /// <summary>
        /// Pomocná vlastnost pro zjištění, zda má být filtrování jak na TCP, tak na UDP.
        /// </summary>
        public bool CaptureAll => (!OnlyTCP && !OnlyUDP) || (OnlyTCP && OnlyUDP);

        [Option('n', HelpText = "Počet paketů, které se mají zobrazit.", Default = 1)]
        public int PacketCountLimit { get; set; } = 1;
    }
}
