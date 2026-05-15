using CommandLine;

namespace uPDF.Sign
{
    [Verb("sign", HelpText = "Sign a PDF document with a digital signature.")]
    public class SignOption
    {
        [Option('m', Required = true, Default = SignMode.SignWithCertificate, HelpText = "The signing mode to use. Options are: SignWithCertificate, CalculateHashOnly, SignDefer.")]
        public SignMode Mode { get; set; }

        [Option('i', Required = true, HelpText = "The input PDF file to be signed.")]
        public string InputFile { get; set; }

        [Option('d', Required = true, HelpText = "The working directory where all the intemediate files are stored")]
        public string WorkingDir { get; set; }

        [Option('c', Required = false, HelpText = "Path to certificate file (e.g., .pfx, .cer) to be used for signing. Required if SignMode <> SignDefer.")]
        public string Certificate { get; set; }

        [Option('p', Required = false, HelpText = "Password for the certificate file, if applicable.")]
        public string CertificatePassword { get; set; }

        [Option('l', Required = false, HelpText = "Path to an image file (e.g., .png, .jpg) to be used as the signature appearance in the PDF. Optional.")]
        public string LogoFile { get; set; }

        [Option('r', Required = false, HelpText = "Reason for signing the document. Optional.")]
        public string Reason { get; set; }

        [Option('o', Required = false, HelpText = "Location where the signing is taking place. Optional.")]
        public string Location { get; set; }

        [Option('x', Required = false, Default = 0, HelpText = "Left position in milimeter where the signature is placed. Optional.")]
        public int XMargin { get; set; }

        [Option('y', Required = false, Default = 0, HelpText = "Top position in milimeter where the signature is placed. Optional.")]
        public int YMargin { get; set; }

        [Option('w', Required = false, Default = 240, HelpText = "Width in milimeter of the signature appearance. Optional.")]
        public int Width { get; set; }

        [Option('h', Required = false, Default = 50, HelpText = "Height in milimeter of the signature appearance. Optional.")]
        public int Height { get; set; }

        [Option('f', Required = false, Default = 6.0f, HelpText = "Font size of the signature appearance. Optional")]
        public float FontSize { get; set; }

        [Option('n', Required = false, Default = 1, HelpText = "Page number where the signature placed. Optional.")]
        public int PageNumber { get; set; }

        [Option('t', Required = false, HelpText = "Text to be included in the signature appearance. Optional.")]
        public string SignatureTextFormat { get; set; }

        [Option('a', Default = false, Required = false, HelpText = "If true, hash the signature bytes using SHA256")]
        public bool HashSignature { get; set; }
    }

    public enum SignMode
    {
        /// <summary>
        /// Sign with a PKCS#12 file containing the certificate and private key.
        /// </summary>
        SignWithCertificate,

        /// <summary>
        /// Sign the PDF document by calculating the hash of the document and signing it with an external signature provider, without including the certificate in the signature. 
        /// This mode is useful when the certificate is not available or when the signing process is performed by a separate service.
        /// </summary>
        CalculateHashOnly,

        /// <summary>
        /// Complete the signing process by providing the signed hash obtained from an external signature provider
        /// </summary>
        SignDefer
    }
}
