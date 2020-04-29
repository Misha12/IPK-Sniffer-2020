using CommandLine;
using IPK_Sniffer.Services.InterfaceListing;
using System;
using System.Collections.Generic;

namespace IPK_Sniffer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var parser = new Parser(config => config.IgnoreUnknownArguments = true);

            parser.ParseArguments<Options>(args)
                .WithParsed(Run)
                .WithNotParsed(ArgumentParseError);
        }

        private static void Run(Options options)
        {
        }

        /// <summary>
        /// Funkce pro zpracování chybně získaných parametrů příkazové řádky.
        /// </summary>
        private static void ArgumentParseError(IEnumerable<Error> errors)
        {
            foreach (var error in errors)
            {
                if (error is MissingValueOptionError valueError && valueError.NameInfo.NameText == "i")
                {
                    InterfaceListing.Process();
                    break;
                }
                else if (error is MissingRequiredOptionError requiredError && requiredError.NameInfo.NameText == "i")
                {
                    InterfaceListing.Process();
                    break;
                }
            }
        }
    }
}
