using System.Security.Cryptography;
using System.Text;

namespace ConsoleEx
{
    // TODO: ВОТ ЭТОТ РАБОЧИЙ
    // https://www.albahari.com/nutshell/E8-CH21.aspx
    internal class Test8
    {
        const string fileName = "encrypted2.bin";
        byte[] key = { 145, 12, 32, 245, 98, 132, 98, 214, 6, 77, 131, 44, 221, 3, 9, 50 };
        //byte[] iv = { 15, 122, 132, 5, 93, 198, 44, 31, 9, 39, 241, 49, 250, 188, 80, 7 };
        //
        //byte[] key = new byte[16];
        //byte[] iv = new byte[16];

        //byte[] key = new byte[32];
        byte[] iv = new byte[16];

        public void Encrypt(string plainText)
        {
            //string wsdaf = Convert.ToBase64String(key);
            //string wsdaf2 = Encoding.UTF8.GetString(key);


            byte[] data = Encoding.UTF8.GetBytes(plainText);
            using (SymmetricAlgorithm algorithm = Aes.Create())
            using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, iv))
            using (Stream f = File.Create(fileName))
            using (Stream c = new CryptoStream(f, encryptor, CryptoStreamMode.Write))
                c.Write(data, 0, data.Length);

            //*******************************************
            //byte[] data = Encoding.UTF8.GetBytes(plainText);
            ////using (MemoryStream ms = new MemoryStream())
            //using (SymmetricAlgorithm algorithm = Aes.Create())
            //{
            //    algorithm.GenerateKey();
            //    algorithm.GenerateIV();
            //    //using (ICryptoTransform encryptor = algorithm.CreateEncryptor(key, iv))
            //    using (ICryptoTransform encryptor = algorithm.CreateEncryptor())
            //    using (Stream f = File.Create(fileName))
            //    using (Stream c = new CryptoStream(f, encryptor, CryptoStreamMode.Write))
            //        c.Write(data, 0, data.Length);
            //}

        }

        public string Decrypt()
        {
            string Decoded;
            using (SymmetricAlgorithm algorithm = Aes.Create())
            using (ICryptoTransform decryptor = algorithm.CreateDecryptor(key, iv))
            using (Stream f = File.OpenRead(fileName))
            using (Stream c = new CryptoStream(f, decryptor, CryptoStreamMode.Read))
            //for (int b; (b = c.ReadByte()) > -1;)
            //    Console.Write(b + " ");
            using (StreamReader sr = new StreamReader(c))
                Decoded = sr.ReadToEnd();
            return Decoded;

            //****************************************************
            //string Decoded;
            //using (SymmetricAlgorithm algorithm = Aes.Create())
            //{
            //    algorithm.GenerateKey();
            //    algorithm.GenerateIV();
            //    using (ICryptoTransform decryptor = algorithm.CreateDecryptor())
            //    using (Stream f = File.OpenRead(fileName))
            //    using (Stream c = new CryptoStream(f, decryptor, CryptoStreamMode.Read))
            //    //for (int b; (b = c.ReadByte()) > -1;)
            //    //    Console.Write(b + " ");
            //    using (StreamReader sr = new StreamReader(c))
            //        Decoded = sr.ReadToEnd();
            //    return Decoded;
            //}

        }
    }
}
