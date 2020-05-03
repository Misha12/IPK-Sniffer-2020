using CommandLine;
using IPK_Sniffer.Services.InterfaceListing;
using IPK_Sniffer.Services.Sniffer;
using System;
using System.Collections.Generic;

namespace IPK_Sniffer
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            Console.CancelKeyPress += Console_CancelKeyPress;

            var parser = new Parser(config => config.IgnoreUnknownArguments = true);

            parser.ParseArguments<Options>(args)
                .WithParsed((options) =>
                {
                    options.Validate();
                    Sniffer.Process(options);
                })
                .WithNotParsed(ArgumentParseError);
        }

        private static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Sniffer.DisposeDevice();
            Environment.Exit(AppCodes.Success);
        }

        /// <summary>
        /// Funkce pro zpracování chybně získaných parametrů příkazové řádky.
        /// </summary>
        private static void ArgumentParseError(IEnumerable<Error> errors)
        {
            foreach (var error in errors)
            {
                if ((error is MissingValueOptionError valueError && valueError.NameInfo.NameText == "i")
                    || (error is MissingRequiredOptionError requiredError && requiredError.NameInfo.NameText == "i")
                )
                {
                    InterfaceListing.Process();
                    Environment.Exit(AppCodes.Success);
                }

                Environment.Exit(AppCodes.InternalError);
            }
        }
    }
}
