using iText.IO.Font;
using iText.IO.Image;
using iText.Kernel.Colors;
using iText.Kernel.Font;
using iText.Kernel.Pdf;
using iText.Kernel.Pdf.Canvas;
using iText.Kernel.Pdf.Xobject;
using iText.Layout;
using iText.Layout.Element;
using iText.Signatures;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Color = System.Drawing.Color;
using Exception = System.Exception;
using Path = System.IO.Path;
using Rectangle = iText.Kernel.Geom.Rectangle;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace uPDF.Sign
{
    public class Signer
    {
        public Signer()
        {
            try
            {
                FontProgramFactory.ClearRegisteredFonts();
                FontProgramFactory.ClearRegisteredFontFamilies();
            }
            catch
            {
                // Ignore any errors when clearing font cache, as it may not be supported in all environments.
            }
        }

        public SignOption Options { get; set; }

        private SigningContext _context;

        private void CalculateCertChain()
        {
            if (Options.Mode == SignMode.SignWithCertificate)
            {
                _context.X509Cert = new X509Certificate2(Options.Certificate, Options.CertificatePassword, X509KeyStorageFlags.Exportable);
                var parser = new X509CertificateParser();
                _context.CertificateChains[0] = parser.ReadCertificate(_context.X509Cert.RawData);

                if (_context.CertificateChains[0] == null)
                {
                    throw new Exception($"Failed to load certificate from {Options.Certificate}.");
                }

                _context.SignerName = _context.CertificateChains[0].SubjectDN.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN)[0].ToString();
            }
            else if (Options.Mode == SignMode.CalculateHashOnly)
            {
                var parser = new X509CertificateParser();
                using (var stream = new FileStream(Options.Certificate, FileMode.Open, FileAccess.Read))
                {
                    _context.CertificateChains[0] = parser.ReadCertificate(stream);
                }

                if (_context.CertificateChains[0] == null)
                {
                    throw new Exception($"Failed to load certificate from {Options.Certificate}.");
                }

                _context.SignerName = _context.CertificateChains[0].SubjectDN.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN)[0].ToString();
            }
        }
        private void SignWithCertificate()
        {
            Options.HashSignature = false; // when signing with certificate, the signature hash is not needed as it will be hashed when running SignWithPrivateKey
            CalculateCertChain();
            GetDocumentHash();
            GetSignatureHash();
            SignInternal(_context.SignatureHash);
            _context.Cleanup(Options.WorkingDir);
        }

        private void SignDefer()
        {
            if (File.Exists(_context.SignedSignatureFile) == false)
            {
                throw new FileNotFoundException($"Signed hash file not found: {_context.SignedSignatureFile}");
            }

            byte[] signedHash = File.ReadAllBytes(_context.SignedSignatureFile);
            CompleteSigning(signedHash);

            _context.Cleanup(Options.WorkingDir);
        }

        private void CalculateHashOnly()
        {
            CalculateCertChain();
            GetDocumentHash();
            GetSignatureHash();
            _context.Save();
        }

        private void InitializeContext()
        {
            if (Options.Mode == SignMode.SignWithCertificate ||
                Options.Mode == SignMode.CalculateHashOnly)
            {
                _context = new SigningContext(Options.WorkingDir, Path.GetFileNameWithoutExtension(Options.InputFile))
                {
                    CertificateChains = new X509Certificate[1]
                };
            }
            else
            {
                _context = new SigningContext(Options.WorkingDir, Path.GetFileNameWithoutExtension(Options.InputFile));
                _context.Load();
            }
        }

        public void Run()
        {
            try
            {
                InitializeContext();

                switch (Options.Mode)
                {
                    case SignMode.SignWithCertificate:
                        SignWithCertificate();
                        break;
                    case SignMode.CalculateHashOnly:
                        CalculateHashOnly();
                        break;
                    case SignMode.SignDefer:
                        SignDefer();
                        break;
                    default:
                        throw new Exception("Invalid signing mode.");
                }
            }
            catch(Exception ex)
            {
                var errFile = Path.Combine(Options.WorkingDir, Path.GetFileNameWithoutExtension(Options.InputFile) + ".err");
                File.WriteAllText(errFile, ex.ToString() + Environment.NewLine + "StackTrace: " + ex.StackTrace);
                throw ex;
            }
        }


        private void GetDocumentHash()
        {
            _context.DocumentHash = CalcNakedHash(Options.InputFile, _context.TempFile, _context.CertificateChains);
        }

        private void GetSignatureHash()
        {
            var sgn = new PdfPKCS7(null, _context.CertificateChains, DigestAlgorithms.SHA256, false);
            var authAttrBytes = sgn.GetAuthenticatedAttributeBytes(_context.DocumentHash, PdfSigner.CryptoStandard.CMS, null, null);
            if (Options.HashSignature)
            {
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                {
                    _context.SignatureHash = sha256.ComputeHash(authAttrBytes);
                }
            }
            else
            {
                _context.SignatureHash = authAttrBytes;
            }
        }

        private void SignInternal(byte[] data)
        {
            var hash = new byte[data.Length];
            Array.Copy(data, hash, data.Length);

            var signedBytes = SignWithPrivateKey(hash);
            CompleteSigning(signedBytes);
        }

        private void CompleteSigning(byte[] signedBytes)
        {
            var encodedSig = signedBytes;
            var sgn = new PdfPKCS7(null, _context.CertificateChains, DigestAlgorithms.SHA256, false);
            sgn.SetExternalDigest(signedBytes, null, "RSA");
            encodedSig = sgn.GetEncodedPKCS7(_context.DocumentHash, PdfSigner.CryptoStandard.CMS, null, null, null);

            SignDefer(_context.TempFile, _context.OutputFile, encodedSig);
        }

        private byte[] SignWithPrivateKey(byte[] hash)
        {
            var rsa = _context.X509Cert.GetRSAPrivateKey();
            var keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
            var signature = new PrivateKeySignature(keyPair.Private, DigestAlgorithms.SHA256);
            return signature.Sign(hash);
        }

        protected string GetLayer2Text()
        {
            if (string.IsNullOrEmpty(Options.SignatureTextFormat))
            {
                Options.SignatureTextFormat = "Signed by {Signer}\nSigned date: " + DateTime.Now.ToString("dd/MM/yyyy") + "\n" + Options.Reason;
            }

            return Options.SignatureTextFormat.Replace("{Signer}", _context.SignerName);
        }

        private byte[] CalcNakedHash(string source, string temp, X509Certificate[] chains)
        {
            using (var reader = new PdfReader(source))
            using (var os = new FileStream(temp, FileMode.OpenOrCreate, FileAccess.Write))
            {
                var signer = new PdfSigner(reader, os, new StampingProperties().UseAppendMode());
                var signatureAppearance = signer.GetSignatureAppearance();

                var pageRect = new Rectangle(
                    Options.XMargin / 25.4f * 72,
                    Options.YMargin / 25.4f * 72,
                    Options.Width, Options.Height);

                signatureAppearance
                    .SetReason(Options.Reason)
                    .SetLocation(Options.Location)
                    .SetRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC)
                    .SetCertificate(chains[0])
                    .SetPageNumber(Options.PageNumber)
                    .SetPageRect(pageRect);

                float h = Options.Height;
                float padding = h * 0.05f;
                float logoW = h;
                float textAreaW = logoW * 2.5f;

                PdfFormXObject layer2 = signatureAppearance.GetLayer2();
                var pdfCanvas = new PdfCanvas(layer2, signer.GetDocument());

                byte[] logoBytes = PrepareLogoImage(Options.LogoFile, (int)(logoW - padding * 2));
                pdfCanvas.AddImageFittedIntoRectangle(
                    ImageDataFactory.CreatePng(logoBytes),
                    new Rectangle(padding, padding, logoW - padding * 2, h - padding * 2),
                    false);

                var fontPath = Path.Combine(
                    Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                    "Quivira.ttf");

                try
                {
                    iText.IO.Font.FontCache.ClearSavedFonts();
                }
                catch
                {
                    // Ignore any errors when clearing font cache, as it may not be supported in all environments.
                }

                byte[] fontBytes = File.ReadAllBytes(fontPath); 
                var font = PdfFontFactory.CreateFont(
                    fontBytes,
                    PdfEncodings.IDENTITY_H,
                    PdfFontFactory.EmbeddingStrategy.FORCE_EMBEDDED
                );

                var textRect = new Rectangle(logoW + padding, padding, textAreaW, h - padding * 2);
                var canvas = new Canvas(pdfCanvas, textRect);

                canvas.SetFont(font)
                      .SetFontSize(Options.FontSize)
                      .SetFontColor(ColorConstants.RED);

                foreach (var line in GetLayer2Text().Split('\n'))
                {
                    var para = new Paragraph(line.TrimEnd('\r'))
                        .SetMargin(0)
                        .SetMultipliedLeading(1.3f);
                    canvas.Add(para);
                }

                canvas.Close();
                pdfCanvas.Release();

                // Stamp the signature visual appearance on all other pages BEFORE signing,
                // so the document is not modified after the signature is applied.
                int totalPages = signer.GetDocument().GetNumberOfPages();
                for (int i = 1; i <= totalPages; i++)
                {
                    if (i == Options.PageNumber) continue;

                    var page = signer.GetDocument().GetPage(i);
                    var pageCanvas = new PdfCanvas(page);
                    pageCanvas.AddXObjectAt(layer2, pageRect.GetX(), pageRect.GetY());
                    pageCanvas.Release();
                }

                signer.SetFieldName(_context.SignatureFieldName);

                var subFilter = PdfName.Adbe_pkcs7_detached;

                var container = new EmptySignatureContainer(PdfName.Adobe_PPKLite, subFilter, DigestAlgorithms.SHA256);
                signer.SignExternalContainer(container, 32000);
                return container.Hash;
            }
        }

        private byte[] PrepareLogoImage(string logoPath, int sizePx)
        {
            using (var logo = System.Drawing.Image.FromFile(logoPath))
            using (var bmp = new Bitmap(sizePx, sizePx, PixelFormat.Format32bppArgb))
            using (var g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.HighQuality;
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.Clear(Color.Transparent);
                g.DrawImage(logo, new System.Drawing.Rectangle(0, 0, sizePx, sizePx));

                using (var ms = new MemoryStream())
                {
                    bmp.Save(ms, ImageFormat.Png);
                    return ms.ToArray();
                }
            }
        }

        private void TryLoadFont()
        {
            var fontPath = Path.Combine(
                    Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                    "Quivira.ttf");

            try
            {
                iText.IO.Font.FontCache.ClearSavedFonts();
                byte[] fontBytes = File.ReadAllBytes(fontPath);
                var font = PdfFontFactory.CreateFont(
                    fontBytes,
                    PdfEncodings.IDENTITY_H,
                    PdfFontFactory.EmbeddingStrategy.FORCE_EMBEDDED
                );
            }
            catch
            {
                // Ignore any errors when clearing font cache, as it may not be supported in all environments.
            }
        }

        private void SignDefer(string tempFile, string targetFile, byte[] signedHash)
        {
            TryLoadFont();
            using (PdfReader reader = new PdfReader(tempFile))
            {
                using (FileStream outStream = new FileStream(targetFile, FileMode.Create, FileAccess.Write))
                {
                    var signedContainer = new SignedSignatureContainer(signedHash);
                    PdfSigner.SignDeferred(new PdfDocument(reader), _context.SignatureFieldName, outStream, signedContainer);
                }
            }
        }
    }
}