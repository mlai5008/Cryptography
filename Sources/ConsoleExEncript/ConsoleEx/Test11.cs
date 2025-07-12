using System.Security.Cryptography;
using System.Text;

namespace ConsoleEx
{
    // TODO: ВОТ ЭТИ РАБОЧИЕ ВАРИАНТЫ
    //https://devtut.github.io/dotnet/encryption-cryptography.html#encrypt-and-decrypt-data-using-aes-in-c
    internal class Test11
    {
        #region Encrypt and decrypt data using AES (in C#)
        //string original = "Here is some data to encrypt!";
        public void EncryptDecrypt(string originalText)
        {
            try
            {
                // Create a new instance of the Aes class.
                // This generates a new key and initialization vector (IV).
                using (Aes myAes = Aes.Create())
                {
                    // Encrypt the string to an array of bytes.
                    byte[] encrypted = EncryptStringToBytes_Aes(originalText, myAes.Key, myAes.IV);

                    // Decrypt the bytes to a string.
                    string roundtrip = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

                    //Display the original data and the decrypted data.
                    Console.WriteLine("Original:   {0}", originalText);
                    Console.WriteLine("Round Trip: {0}", roundtrip);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {0}", e.Message);
            }
        }

        private byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            byte[] encrypted;

            // Create an Aes object with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }

                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        private string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold the decrypted text.
            string plaintext = null;

            // Create an Aes object with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
        #endregion

        //**********************************

        #region Create a Key from a Password / Random SALT (in C#)
        public void CreateKeyEncryptDecrypt()
        {
            Console.WriteLine("Enter a password to produce a key:");

            byte[] pwd = Encoding.Unicode.GetBytes("Password");

            byte[] salt = CreateRandomSalt(7);
            //byte[] salt = new byte[0];

            // Create a TripleDESCryptoServiceProvider object.
            TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();

            try
            {
                Console.WriteLine("Creating a key with PasswordDeriveBytes...");

                // Create a PasswordDeriveBytes object and then create
                // a TripleDES key from the password and salt.
                PasswordDeriveBytes pdb = new PasswordDeriveBytes(pwd, salt);

                // Create the key and set it to the Key property
                // of the TripleDESCryptoServiceProvider object.
                tdes.Key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, tdes.IV);

                Console.WriteLine("Operation complete.");


                string plainText = "Here is some data to encrypt!";
                byte[] plainTextArray = Encoding.UTF8.GetBytes(plainText);

                ICryptoTransform encryptor = tdes.CreateEncryptor();
                byte[] resultArray = encryptor.TransformFinalBlock(plainTextArray, 0, plainTextArray.Length);                
                string cipherText = Convert.ToBase64String(resultArray, 0, resultArray.Length);

                byte[] cipherTextArray = Convert.FromBase64String(cipherText);
                ICryptoTransform decryptor = tdes.CreateDecryptor();
                byte[] decryptArray = decryptor.TransformFinalBlock(cipherTextArray, 0, cipherTextArray.Length);                

                //Convert and return the decrypted data/byte into string format.
                string decryptText = Encoding.UTF8.GetString(decryptArray);

                Console.WriteLine(plainText);
                Console.WriteLine(cipherText);
                Console.WriteLine(decryptText);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                // Clear the buffers
                ClearBytes(pwd);
                ClearBytes(salt);

                // Clear the key.
                tdes.Clear();
            }            
        }
        #region Helper methods

        /// <summary>
        /// Generates a random salt value of the specified length.
        /// </summary>
        public static byte[] CreateRandomSalt(int length)
        {
            // Create a buffer
            byte[] randBytes;

            if (length >= 1)
            {
                randBytes = new byte[length];
            }
            else
            {
                randBytes = new byte[1];
            }

            // Create a new RNGCryptoServiceProvider.
            RNGCryptoServiceProvider rand = new RNGCryptoServiceProvider();

            // Fill the buffer with random bytes.
            rand.GetBytes(randBytes);

            // return the bytes.
            return randBytes;
        }

        /// <summary>
        /// Clear the bytes in a buffer so they can't later be read from memory.
        /// </summary>
        public static void ClearBytes(byte[] buffer)
        {
            // Check arguments.
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }

            // Set each byte in the buffer to 0.
            for (int x = 0; x < buffer.Length; x++)
            {
                buffer[x] = 0;
            }
        }
        #endregion
        #endregion

        //**********************************

        #region Encryption and Decryption using Cryptography (AES)

        // РАБОТАЕТ ПРИ ЛЮБЫХ ВАРИАНТАХ
        private const string Password = "z20ds5898a4e5523bbce3ea1025a1916";
        //private const string Password = "CryptKey";
        //private const string Password = "1";

        byte[] salt = new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 };
        //byte[] salt = new byte[16];
        //byte[] salt = new byte[8];
        //byte[] salt = new byte[1];
        //byte[] salt = new byte[] { 0x49, 0x76 };

        public string Encrypt(string originText)
        {
            if (originText == null) return string.Empty;
            string cipherText = string.Empty;

            byte[] originTextBytes = Encoding.Unicode.GetBytes(originText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(Password, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(originTextBytes, 0, originTextBytes.Length);
                        cs.Close();
                    }

                    cipherText = Convert.ToBase64String(ms.ToArray());
                }
            }
            return cipherText;
        }

        public string Decrypt(string cipherText)
        {
            if(cipherText == null) return string.Empty;
            string originText = string.Empty;

            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(Password, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }

                    originText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }

            return originText;
        }
        #endregion
    }
}
