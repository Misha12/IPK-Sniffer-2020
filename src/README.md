# IPK Packet Sniffer

## Autor

Halabica Michal (xhalab00)

## Popis

Aplikace pro naslouchání packetů na specifikovaném rozhraní a výpis na standardní výstup. Aplikace je psaná v jazyce C# běžící na platformě .NET Core 3.1.

Aplikace podporuje výpis TCP, UDP a ICMP packetů. Zbylé packety jsou ignorovány. K překladu doménového názvu ve výpisu se používá DNS resolving lokální stanice obohacenou o cache.

### Závislosti

Aplikace vyžaduje jak pro překlad, tak spuštění nainstalovanou platformu [.NET Core 3.1](https://dotnet.microsoft.com/download/dotnet-core/3.1).

Při překladu si aplikace stáhne z [NuGet](https://www.nuget.org/) následující knihovny:

- [CommandLineParser](https://www.nuget.org/packages/CommandLineParser/) ([GitHub](https://github.com/commandlineparser/commandline)) - Knihovna pro zpracování parametrů příkazové řádky.
- [SharpPcap](https://www.nuget.org/packages/SharpPcap/) ([GitHub](https://github.com/chmorgan/sharppcap)) - Knihovna pro multiplatformní práci s knihovnami [WinPcap (Windows)](https://www.winpcap.org/) a [LibPcap (Unix)](https://www.tcpdump.org/) zajišťující práci se síťovým rozhraním.

## Překlad

Aplikaci lze přeložit pomocí příkazu `make build`, který spouští následující příkat:
```sh
dotnet build ipk-sniffer/ -c Release -o build/
```
Tento příkaz vytvoří adresář `build`, ve kterém se bude nacházet přeložená aplikace. Současně, jak bylo zmíněno v předchozí kapitole, tak si překladač automaticky stáhne potřebné knihovny.

## Spuštění

Po úspěšném překladu lze aplikaci spustit následujícím příkazem:
```sh
cd build;
sudo ./ipk-sniffer -i interface [-p port1,port2,...] [--tcp|-t] [--udp|u] [--icmp] [-n count]
```

### Prametry

- `-i`: Název rozhraní, na kterém se mají sledovat packety. Pokud bylo zadán pouze parametr `-i` bez hodnoty, nebo tento parametr nebyl vůbec zadán, tak se vypíše seznam aktivních rozhraní.
- `-p port`: Pokud je zadána jeho hodnota, tak se vypisují pouze packety zachycené na daných portech. Tento parametr nemá vliv na ICMP packety. Jako oddělovač se používá znak `,` (čárka).
- `-t`, nebo `--tcp`: Omezí sledování na TCP packety.
- `-u`, nebo `--udp`: Omezí sledování na UDP packety.
- `--icmp`: Omezí sledování na ICMP packety.
- `-n count`: Omezí sledování pouze na určitý počet packetů. Výchozí hodnota je 1. Možno zadat hodnoty z rozsahu <1; INT_MAX>.

Parametry `-t/--tcp`, `-u/--udp` a `--icmp` lze mezi sebou kombinovat. Pokud nebude žádný zadán, tak je to chápáno jako by byly zadány všechny tři.

### Rozšíření
- Podpora ICMP packetů.
- Možnost zadat více sledovaných portů.

## Nedostatky

- Inicializace aplikace při jejím spuštění má vysoké časy. (V rámci vteřin).
