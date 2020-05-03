using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace IPK_Sniffer.Services.InterfaceListing
{
    /// <summary>
    /// Získání seznamu aktivních rozhraní.
    /// </summary>
    public static class InterfaceListing
    {
        public static void Process()
        {
            var devices = CaptureDeviceList.New();

            foreach (var device in devices.OfType<LibPcapLiveDevice>())
            {
                try
                {
                    device.Open(DeviceMode.Promiscuous);

                    var builder = new StringBuilder()
                        .Append("Name: ").AppendLine(device.Name);

                    if(!string.IsNullOrEmpty(device.Interface.FriendlyName) && device.Interface.FriendlyName != device.Name)
                        builder.Append("FriendlyName: ").AppendLine(device.Interface.FriendlyName);

                    var ipv4Adresses = device.Interface.Addresses.Where(IsIPV4).ToList();
                    var ipv6Adresses = device.Interface.Addresses.Where(IsIPV6).ToList();

                    if (ipv4Adresses.Count == 0 || ipv6Adresses.Count == 0)
                        continue;

                    if (ipv4Adresses.Count > 0)
                        builder.Append("Addresses (IPv4): ").AppendLine(string.Join(", ", ipv4Adresses.Select(FormatIPAddress).Where(o => o != null)));
                    if (ipv6Adresses.Count > 0)
                        builder.Append("Addresses (IPv6): ").AppendLine(string.Join(", ", ipv6Adresses.Select(FormatIPAddress).Where(o => o != null)));

                    var ipv4GatewayAddresses = device.Interface.GatewayAddresses?.Where(IsIPV4).ToList() ?? new List<IPAddress>();
                    var ipv6GatewayAddresses = device.Interface.GatewayAddresses?.Where(IsIPV6).ToList() ?? new List<IPAddress>();

                    if (ipv4GatewayAddresses.Count > 0)
                        builder.Append("Gateway addresses (IPv4): ").AppendLine(string.Join(", ", ipv4GatewayAddresses.Select(o => o.ToString())));
                    if (ipv6GatewayAddresses.Count > 0)
                        builder.Append("Gateway addresses (IPv6): ").AppendLine(string.Join(", ", ipv6GatewayAddresses.Select(o => o.ToString())));

                    Console.WriteLine(builder.ToString());
                }
                catch(PcapException)
                {
                    // Pro účely zjištění seznamu aktivních rozhraní je vyjímka zbytečná.
                    continue;
                }
                finally
                {
                    if(device.Opened)
                        device.Close();
                }
            }
        }

        /// <summary>
        /// Funkce pro formátování IP adresy do čitelného formátu.
        /// </summary>
        /// <param name="address">Adresa rozhraní.</param>
        /// <returns>
        /// Naformátovaná podoba adresy. Pokud byla parametru 'address' null, nebo se jedná o HW adresu, tak se vrací null.
        /// </returns>
        private static string FormatIPAddress(PcapAddress address) => address?.Addr?.type == null || address.Addr.type == Sockaddr.AddressTypes.HARDWARE ? null : address?.Addr?.ToString();

        /// <summary>
        /// Detekce, zda je adresa IPv4.
        /// </summary>
        private static bool IsIPV4(PcapAddress address) => address.Addr?.type != Sockaddr.AddressTypes.HARDWARE && IsIPV4(address.Addr?.ipAddress);

        /// <summary>
        /// Detekce, zda je adresa IPv4.
        /// </summary>
        private static bool IsIPV4(IPAddress address) => address != null && address.AddressFamily == AddressFamily.InterNetwork;

        /// <summary>
        /// Detekce, zda je adresa IPv6.
        /// </summary>
        private static bool IsIPV6(PcapAddress address) => address.Addr?.type != Sockaddr.AddressTypes.HARDWARE && IsIPV6(address.Addr?.ipAddress);

        /// <summary>
        /// Detekce, zda je adresa IPv6.
        /// </summary>
        private static bool IsIPV6(IPAddress address) => address != null && address.AddressFamily == AddressFamily.InterNetworkV6;
    }
}
