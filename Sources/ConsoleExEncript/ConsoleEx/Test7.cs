using System.Security.Cryptography;
using System.Text;

namespace ConsoleEx
{
    internal class Test7
    {
        private const string SecurityKey = "ComplexKeyHere_12121";
        //private const string SecurityKey = "1";
        //private const string SecurityKey = "z20ds5898a4e5523bbce3ea1025a1916z20ds5898a4e5523bbce3ea1025a1916z20ds5898a4e5523bbce3ea1025a1916";

        //byte[] key = { 145, 12, 32, 245, 98, 132, 98, 214, 6, 77, 131, 44, 221, 3, 9, 50 };
        //byte[] iv = { 15, 122, 132, 5, 93, 198, 44, 31, 9, 39, 241, 49, 250, 188, 80, 7 };

        //byte[] data = { 1, 2, 3, 4, 5 };   // This is what we're encrypting.

        //using (SymmetricAlgorithm algorithm = Aes.Create())
        //using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, iv))
        //using (Stream f = File.Create("encrypted.bin"))
        //using (Stream c = new CryptoStream(f, encryptor, CryptoStreamMode.Write))
        //    c.Write(data, 0, data.Length);

        //byte[] decrypted = new byte[5];

        //using (SymmetricAlgorithm algorithm = Aes.Create())
        //using (ICryptoTransform decryptor = algorithm.CreateDecryptor(key, iv))
        //using (Stream f = File.OpenRead("encrypted.bin"))
        //using (Stream c = new CryptoStream(f, decryptor, CryptoStreamMode.Read))
        //    for (int b; (b = c.ReadByte()) > -1;)
        //        Console.Write(b + " ");

        public string Encrypt(string plainText)
        {
            //using (SymmetricAlgorithm algorithm = Aes.Create())
            //using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, iv))
            //using (Stream f = File.Create("encrypted.bin"))
            //using (Stream c = new CryptoStream(f, encryptor, CryptoStreamMode.Write))
            //    c.Write(data, 0, data.Length);

            SHA256 objMD5CryptoService = SHA256.Create();
            //Gettting the bytes from the Security Key and Passing it to compute the Corresponding Hash Value.
            byte[] securityKeyArray = objMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SecurityKey));
            //De-allocatinng the memory after doing the Job.
            objMD5CryptoService.Clear();

            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = securityKeyArray;
                //aes.IV = iv;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor();

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter((Stream)cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return Convert.ToBase64String(array);
        }

        public string Decrypt(string cipherText)
        {
            //string dataS = String.Empty;
            //using (SymmetricAlgorithm algorithm = Aes.Create())
            //using (ICryptoTransform decryptor = algorithm.CreateDecryptor(key, iv))
            //using (Stream f = File.OpenRead("encrypted.bin"))
            //using (Stream c = new CryptoStream(f, decryptor, CryptoStreamMode.Read))
            ////for (int b; (b = c.ReadByte()) > -1;)
            ////    Console.Write(b + " ");
            //using (StreamReader reader = new StreamReader(c))
            //    dataS = reader.ReadToEnd(); // вот это важно здесь
            //return dataS;

            byte[] buffer = Convert.FromBase64String(cipherText);

            SHA256 objMD5CryptoService = SHA256.Create();
            //Gettting the bytes from the Security Key and Passing it to compute the Corresponding Hash Value.
            byte[] securityKeyArray = objMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SecurityKey));
            //De-allocatinng the memory after doing the Job.
            objMD5CryptoService.Clear();

            using (Aes aes = Aes.Create())
            {
                aes.Key = securityKeyArray;
                //aes.IV = iv;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.PKCS7;
                ICryptoTransform decryptor = aes.CreateDecryptor();
                string Decoded;
                using (MemoryStream memoryStream = new MemoryStream(buffer))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        //using (StreamReader streamReader = new StreamReader(cryptoStream))
                        //{
                        //    return streamReader.ReadToEnd();
                        //}
                        //cryptoStream.Read(buffer, 0, buffer.Length);
                        //cryptoStream.FlushFinalBlock();
                        //return Encoding.Unicode.GetString(memoryStream.ToArray());
                        using (StreamReader sr = new StreamReader(cryptoStream))
                            Decoded = sr.ReadToEnd();
                        return Decoded;
                    }
                }
            }
        }
    }
}
