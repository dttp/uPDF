using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
namespace uPDF.Sign
{
    public class SigningContext
    {
        public string TempFile { get; set; }
        public string OutputFile { get; set; }

        public string SignerName { get; set; }
        public byte[] DocumentHash { get; set; }

        public byte[] SignatureHash { get; set; } 

        public string SignatureFieldName { get; set; }

        public string SignatureFile { get; set; }

        public string SignedSignatureFile { get; set; }

        [JsonIgnore]
        public X509Certificate[] CertificateChains { get; set; }

        [JsonIgnore]
        public X509Certificate2 X509Cert;

        private string _workingDir;
        private string _inputFileName;
        public SigningContext(string workingDir, string inputFileName)
        {
            _workingDir = workingDir;
            _inputFileName = inputFileName;
            
            TempFile = Path.Combine(_workingDir, inputFileName + "_intermediate.pdf");
            OutputFile = Path.Combine(_workingDir, inputFileName + "_signed.pdf");
            SignatureFile = Path.Combine(_workingDir, inputFileName + ".sig");
            SignedSignatureFile = Path.Combine(workingDir, inputFileName + "_signed_hash.bin");
            SignatureFieldName = Guid.NewGuid().ToString("N");
        }

        public void Save()
        {
            var filePath = Path.Combine(_workingDir, _inputFileName + ".ctx");
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,              // Pretty print
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase, // camelCase keys
                PropertyNameCaseInsensitive = true, // case-insensitive deserialization,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull // bỏ null fields
            };

            var json = JsonSerializer.Serialize(this, options);
            File.WriteAllText(filePath, json);

            File.WriteAllBytes(this.SignatureFile, this.SignatureHash);
        }

        public void Load()
        {
            var filePath = Path.Combine(_workingDir, _inputFileName + ".ctx");
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"Signing context file not found: {filePath}");
            }
            var json = File.ReadAllText(filePath);
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,              // Pretty print
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase, // camelCase keys
                PropertyNameCaseInsensitive = true, // case-insensitive deserialization,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull // bỏ null fields
            };
            var context = JsonSerializer.Deserialize<SigningContext>(json, options);
            if (context != null)
            {
                this.DocumentHash = context.DocumentHash;
                this.OutputFile = context.OutputFile;
                this.SignerName = context.SignerName;
                this.SignatureFieldName = context.SignatureFieldName;
                this.TempFile = context.TempFile;
                this.SignatureFile = context.SignatureFile;
                this.SignatureHash = context.SignatureHash;
            }
        }

        public void Cleanup(string workingDir)
        {
            var contextFilePath = Path.Combine(_workingDir, _inputFileName + ".ctx");
            if (File.Exists(contextFilePath))
            {
                File.Delete(contextFilePath);
            }
            if (File.Exists(TempFile))
            {
                File.Delete(TempFile);
            }

            if (File.Exists(SignatureFile))
            {
                File.Delete(SignatureFile);
            }

            if (File.Exists(SignedSignatureFile))
            {
                File.Delete(SignedSignatureFile);
            }
        }
    }
}
