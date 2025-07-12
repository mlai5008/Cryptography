using System.Security.Cryptography;
using System.Text;

namespace ConsoleEx
{
    // https://www.codeproject.com/Articles/15379/Password-protecting-IO-streams
    internal class Test9
    {
        private const string fileName = "encrypted9.bin";
        private const string salt = "Testy";

        string password = "Password";
        //byte[] data = Encoding.UTF8.GetBytes(salt);
        byte[] pdbsalt = new byte[16];
        byte[] key = null;
        byte[] iv = new byte[16];

        public Test9()
        {
            PasswordDeriveBytes pdb = new PasswordDeriveBytes(password, pdbsalt);
            key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, iv);
        }

        public void Encrypt(string plainText)
        { 
            byte[] data = Encoding.UTF8.GetBytes(plainText);
            using (SymmetricAlgorithm algorithm = Aes.Create())
            using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, iv))
            using (Stream f = File.Create(fileName))
            using (Stream c = new CryptoStream(f, encryptor, CryptoStreamMode.Write))
                c.Write(data, 0, data.Length);
        }

        public string Decrypt()
        {
            string Decoded;
            using (SymmetricAlgorithm algorithm = Aes.Create())
            using (ICryptoTransform decryptor = algorithm.CreateDecryptor(key, iv))
            using (Stream f = File.OpenRead(fileName))
            using (Stream c = new CryptoStream(f, decryptor, CryptoStreamMode.Read))            
            using (StreamReader sr = new StreamReader(c))
                Decoded = sr.ReadToEnd();
            return Decoded;
        }
    }
}
