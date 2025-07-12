using System.Security.Cryptography;
using System.Text;

namespace ConsoleEx
{
    internal class Test12
    {
        // TODO: ВОТ ЭТОТ РАБОЧИЙ        
        private readonly byte[] salt = new byte[8];

        public void EncryptToFile(string originText, string fileName, string password)
        {
            if (string.IsNullOrWhiteSpace(originText)) throw new ArgumentNullException(nameof(originText));

            byte[] originTextBytes = Encoding.Unicode.GetBytes(originText);
            using (SymmetricAlgorithm algorithm = Aes.Create())
            using (Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, salt))
            using (ICryptoTransform encryptor = algorithm.CreateEncryptor(pdb.GetBytes(32), pdb.GetBytes(16)))
            //using (Stream fStream = File.Create(fileName))
            using (Stream fWrite = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None))
            using (Stream cStream = new CryptoStream(fWrite, encryptor, CryptoStreamMode.Write))
                cStream.Write(originTextBytes, 0, originTextBytes.Length);

            #region Temp
            //******************************
            //// Работает
            //byte[] originTextBytes = Encoding.Unicode.GetBytes(originText);
            //using (SymmetricAlgorithm algorithm = Aes.Create())
            //using (Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(Password, salt))
            //{
            //    algorithm.Key = pdb.GetBytes(32);
            //    algorithm.IV = pdb.GetBytes(16);
            //    using (ICryptoTransform encryptor = algorithm.CreateEncryptor())
            //    using (Stream fWrite = new FileStream(fileName, FileMode.Create, FileAccess.Write, FileShare.None))
            //    using (Stream cStream = new CryptoStream(fWrite, encryptor, CryptoStreamMode.Write))
            //        cStream.Write(originTextBytes, 0, originTextBytes.Length);
            //} 
            #endregion
        }

        public string DecryptFromFile(string fileName, string password)
        {
            string originText = string.Empty;
            using (SymmetricAlgorithm algorithm = Aes.Create())
            using (Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, salt))
            using (ICryptoTransform decryptor = algorithm.CreateDecryptor(pdb.GetBytes(32), pdb.GetBytes(16)))
            //using (Stream f = File.OpenRead(fileName))
            using (Stream fRead = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (Stream c = new CryptoStream(fRead, decryptor, CryptoStreamMode.Read))
            using (StreamReader sr = new StreamReader(c, Encoding.Unicode))
                originText = sr.ReadToEnd();
            return originText;
        }
    }
}
