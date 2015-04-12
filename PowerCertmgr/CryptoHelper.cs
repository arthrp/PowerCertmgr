using System;

namespace MonoSecurityTools
{
    public static class CryptoHelper
    {
        /// <summary>
        /// Get algorithm name from certificate object identifier
        /// </summary>
        public static string HashAlgNameFromOid (string oid)
        {
            switch (oid) {
                case "1.2.840.113549.1.1.2":    // MD2 with RSA encryption 
                    return "MD2";
                case "1.2.840.113549.1.1.3":    // MD4 with RSA encryption 
                    return "MD4";
                case "1.2.840.113549.1.1.4":    // MD5 with RSA encryption 
                    return "MD5";
                case "1.2.840.113549.1.1.5":    // SHA-1 with RSA Encryption 
                case "1.3.14.3.2.29":       // SHA1 with RSA signature 
                case "1.2.840.10040.4.3":   // SHA1-1 with DSA
                    return "SHA1";
                case "1.2.840.113549.1.1.11":   // SHA-256 with RSA Encryption
                    return "SHA256";
                case "1.2.840.113549.1.1.12":   // SHA-384 with RSA Encryption
                    return "SHA384";
                case "1.2.840.113549.1.1.13":   // SHA-512 with RSA Encryption
                    return "SHA512";
                case "1.3.36.3.3.1.2":
                    return "RIPEMD160";
                default:
                    return "Unknown";
            }
        }
    }
}

