using System.Security.Cryptography;
using System.Text;

namespace ConsoleEx
{
    internal class Test2
    {
        //https://www.codeproject.com/Articles/6465/Using-CryptoStream-in-C
        public void Encrypt()
        {
            FileStream stream = new FileStream("test2.txt", FileMode.OpenOrCreate, FileAccess.Write);

            DESCryptoServiceProvider cryptic = new DESCryptoServiceProvider();
            cryptic.Key = ASCIIEncoding.ASCII.GetBytes("ABCDEFGH");
            cryptic.IV = ASCIIEncoding.ASCII.GetBytes("ABCDEFGH");

            CryptoStream crStream = new CryptoStream(stream, cryptic.CreateEncryptor(), CryptoStreamMode.Write);
            byte[] data = ASCIIEncoding.ASCII.GetBytes("Hello World!");

            crStream.Write(data, 0, data.Length);

            crStream.Close();
            stream.Close();
        }

        public string Decrypt()
        {
            FileStream stream = new FileStream("test2.txt", FileMode.Open, FileAccess.Read);

            DESCryptoServiceProvider cryptic = new DESCryptoServiceProvider();

            cryptic.Key = ASCIIEncoding.ASCII.GetBytes("ABCDEFGH");
            cryptic.IV = ASCIIEncoding.ASCII.GetBytes("ABCDEFGH");

            CryptoStream crStream = new CryptoStream(stream, cryptic.CreateDecryptor(), CryptoStreamMode.Read);
            StreamReader reader = new StreamReader(crStream);

            string data = reader.ReadToEnd();

            reader.Close();
            stream.Close();

            return data;
        }
    }
}
