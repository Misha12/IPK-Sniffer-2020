namespace IPK_Sniffer
{
    /// <summary>
    /// Kódy používané v aplikaci.
    /// </summary>
    public static class AppCodes
    {
        /// <summary>
        /// Korektní ukončení aplikace.
        /// </summary>
        public const int Success = 0;

        /// <summary>
        /// Neplatné rozhraní.
        /// </summary>
        public const int InvalidInterface = 1;

        /// <summary>
        /// Chyba v knihovně LibPcap/SharpPcap;
        /// </summary>
        public const int LibPcapError = 2;

        /// <summary>
        /// Obecná chyba v aplikaci.
        /// </summary>
        public const int InternalError = 99;

        /// <summary>
        /// Byl zadán neplatný port.
        /// </summary>
        public const int InvalidInputPort = 3;
    }
}
