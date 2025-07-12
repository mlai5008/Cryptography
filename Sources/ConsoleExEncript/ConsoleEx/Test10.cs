using System.Security.Cryptography;
using System.Text;

namespace ConsoleEx
{
    public static class Helper
    {
        /// <summary>
        /// Encrypts the value by password and salt.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>The encrypted bytes</returns>
        public static byte[] PasswordEncrypt(this byte[] value, string password, string salt)
        {
            if (value == null) throw new ArgumentNullException("value");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");
            if (string.IsNullOrEmpty(salt)) throw new ArgumentNullException("salt");

            byte[] retVal = null;
            Rijndael rijndaelAlg = CreateRijndael(password, salt);

            using (MemoryStream memoryStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream,rijndaelAlg.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(value, 0, value.Length);
                cryptoStream.Close();
                retVal = memoryStream.ToArray();
            }
            return retVal;
        }


        /// <summary>
        /// Decrypts the value by password and salt.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="password">The password.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>The decrypted bytes</returns>
        public static byte[] PasswordDecrypt(this byte[] value, string password, string salt)
        {
            if (value == null) throw new ArgumentNullException("value");
            if (string.IsNullOrEmpty(password)) throw new ArgumentNullException("password");
            if (string.IsNullOrEmpty(salt)) throw new ArgumentNullException("salt");

            byte[] retVal = null;
            Rijndael rijndaelAlg = CreateRijndael(password, salt);

            using (MemoryStream memoryStream = new MemoryStream())
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream,rijndaelAlg.CreateDecryptor(),CryptoStreamMode.Write))
            {
                cryptoStream.Write(value, 0, value.Length);
                cryptoStream.Close();
                retVal = memoryStream.ToArray();
            }

            return retVal;
        }

        ///// <summary>
        ///// Ecrypts the value to a url encoded string.
        ///// </summary>
        ///// <param name="value">The value.</param>
        ///// <param name="password">The password.</param>
        ///// <param name="salt">The salt.</param>
        ///// <returns>The encrypted and url encoded string</returns>
        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1055:UriReturnValuesShouldNotBeStrings", Justification = "This method does not return a Uri.")]
        //public static string UrlEncodedPasswordEncrypt(this string value, string password, string salt)
        //{
        //    if (value == null)
        //    {
        //        throw new ArgumentNullException("value");
        //    }

        //    if (string.IsNullOrEmpty(password))
        //    {
        //        throw new ArgumentNullException("password");
        //    }

        //    if (string.IsNullOrEmpty(salt))
        //    {
        //        throw new ArgumentNullException("salt");
        //    }

        //    string retVal = null;

        //    byte[] bytesToEncrypt = Encoding.Unicode.GetBytes(value);
        //    byte[] encryptedValue = bytesToEncrypt.PasswordEncrypt(password, salt);
        //    retVal = HttpServerUtility.UrlTokenEncode(encryptedValue);

        //    return retVal;
        //}

        ///// <summary>
        ///// Decrypts the url encoded value.
        ///// </summary>
        ///// <param name="value">The value.</param>
        ///// <param name="password">The password.</param>
        ///// <param name="salt">The salt.</param>
        ///// <returns>The decrypted and url decoded string</returns>
        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1055:UriReturnValuesShouldNotBeStrings", Justification = "This method does not return a Uri.")]
        //public static string UrlEncodedPasswordDecrypt(this string value, string password, string salt)
        //{
        //    if (value == null)
        //    {
        //        throw new ArgumentNullException("value");
        //    }

        //    if (string.IsNullOrEmpty(password))
        //    {
        //        throw new ArgumentNullException("password");
        //    }

        //    if (string.IsNullOrEmpty(salt))
        //    {
        //        throw new ArgumentNullException("salt");
        //    }

        //    string retVal = null;

        //    byte[] bytesToDecrypt = HttpServerUtility.UrlTokenDecode(value);
        //    byte[] decryptedValue = bytesToDecrypt.PasswordDecrypt(password, salt);
        //    retVal = Encoding.Unicode.GetString(decryptedValue);

        //    return retVal;
        //}

        private static Rijndael CreateRijndael(string password, string salt)
        {
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            //byte[] saltBytes = new byte[8];

            PasswordDeriveBytes passwordDeriveBytes = new PasswordDeriveBytes(password,  saltBytes);

            //  Aes
            Rijndael rijndael = Rijndael.Create();
            rijndael.Key = passwordDeriveBytes.GetBytes(32);
            rijndael.IV = passwordDeriveBytes.GetBytes(16);

            return rijndael;
        }
    }
    internal class Test10
    {
        private const string salt = "SaltHash";
        private const string password = "Password";

        public string Encrypt(string plainText)
        {
            byte[] data = Encoding.UTF8.GetBytes(plainText);
            //byte[] data = Convert.FromBase64String(plainText);
            byte[] ddd = data.PasswordEncrypt(password, salt);
            string rdf = Encoding.UTF8.GetString(ddd);
            //string rdf = Convert.ToBase64String(ddd);
            return rdf;
        }

        public string Decrypt(string cipherText)
        {
            byte[] data = Encoding.UTF8.GetBytes(cipherText);
            //byte[] data = Convert.FromBase64String(cipherText);
            byte[] ddd = data.PasswordDecrypt(password, salt);
            string rdf = Encoding.UTF8.GetString(ddd);
            //string rdf = Convert.ToBase64String(ddd);
            return rdf;
        }
    }
}
