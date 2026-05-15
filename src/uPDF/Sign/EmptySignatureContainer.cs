using System;
using System.IO;
using iText.Kernel.Pdf;
using iText.Signatures;
using Org.BouncyCastle.Security;

namespace uPDF.Sign
{
    public class EmptySignatureContainer : IExternalSignatureContainer
    {
        private readonly PdfDictionary _sigDic;
        public byte[] Hash;
        public string Algorithm { get; set; }

        public byte[] Sign(Stream data)
        {

            try
            {
                this.Hash = DigestAlgorithms.Digest(data, DigestUtilities.GetDigest(Algorithm));
            }
            catch (IOException e)
            {
                throw new GeneralSecurityException("EmptySignatureContainer signing exception", e);
            }

            return Array.Empty<byte>();
        }

        public void ModifySigningDictionary(PdfDictionary signDic)
        {
            signDic.PutAll(_sigDic);
        }

        public EmptySignatureContainer(PdfName filter, PdfName subFilter, string algorithm)
        {
            _sigDic = new PdfDictionary();
            _sigDic.Put(PdfName.Filter, filter);
            _sigDic.Put(PdfName.SubFilter, subFilter);
            this.Algorithm = algorithm;
        }
    }

}
