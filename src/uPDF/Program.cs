using CommandLine;
using System;
using uPDF.Sign;

namespace uPDF
{
    internal class Program
    {
        static void Main(string[] args)
        {
            var result = CommandLine.Parser.Default.ParseArguments<SignOption>(args)
                .WithParsed(options =>
                {
                    try
                    {
                        var signer = new Signer
                        {
                            Options = options
                        };
                        signer.Run();
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error: {ex.Message}");
                        Environment.Exit(1);
                    }
                })
                .WithNotParsed(errors =>
                {
                    // Handle parsing errors if needed
                    Environment.Exit(1);
                });
        }
    }
}
