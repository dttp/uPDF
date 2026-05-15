using System.IO;
using iText.Kernel.Pdf;
using iText.Signatures;

namespace uPDF.Sign
{
    public class SignedSignatureContainer : ExternalBlankSignatureContainer
    {
        public byte[] SignedHash { get; set; }

        public SignedSignatureContainer(byte[] signedHash) : base(new PdfDictionary())
        {
            this.SignedHash = signedHash;
        }

        public override byte[] Sign(Stream data)
        {
            return this.SignedHash;
        }
    }
}
