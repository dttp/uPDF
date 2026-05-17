namespace uPDF.Sign
{
    public static class SignOptionHelper
    {
        /// <summary>
        /// Resolves the SignatureTextFormat value. If the value starts with '@',
        /// it is treated as a file path and the contents are read from that file.
        /// This allows multiline text to be passed without command-line newline issues.
        /// </summary>
        public static string ResolveSignatureTextFormat(string value)
        {
            if (string.IsNullOrEmpty(value))
                return value;

            if (value.StartsWith("@"))
            {
                string filePath = value.Substring(1);
                if (System.IO.File.Exists(filePath))
                    return System.IO.File.ReadAllText(filePath);

                throw new System.IO.FileNotFoundException(
                    $"Signature text file not found at: {filePath}");
            }

            return value;
        }
    }
}