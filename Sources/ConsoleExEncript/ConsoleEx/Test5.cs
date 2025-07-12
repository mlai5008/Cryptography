using System.Security.Cryptography;

namespace ConsoleEx
{
    // TODO: ВОТ ЭТОТ РАБОЧИЙ
    internal class Test5
    {
        public byte[] EncryptString(string Original)
        {
            //string Original = "foo bar, this is an example";
            byte[] ToBase64;
            
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, new ToBase64Transform(),  CryptoStreamMode.Write))
            using (StreamWriter st = new StreamWriter(cs))
            {
                st.Write(Original);
                st.Flush();

                ToBase64 = ms.ToArray();
            }

            return ToBase64;
        }

        public string DecryptString(byte[] ToBase64)
        {
            //string Original = "foo bar, this is an example";
            //byte[] ToBase64;
            string Decoded;
            using (MemoryStream ms = new MemoryStream(ToBase64))
            using (CryptoStream cs = new CryptoStream(ms, new FromBase64Transform(), CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(cs))
                Decoded = sr.ReadToEnd();
            return Decoded;
            //Console.WriteLine(Original);
            //Console.WriteLine(Encoding.Default.GetString(ToBase64));
            //Console.WriteLine(Decoded);
        }
    }
}
