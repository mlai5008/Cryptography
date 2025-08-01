﻿using System.Text;
using System.Security.Cryptography;

namespace ConsoleEx
{
    // TODO: ВОТ ЭТОТ РАБОЧИЙ
    internal class Test6
    {
        //This security key should be very complex and Random for encrypting the text. This playing vital role in encrypting the text.
        //private const string SecurityKey = "ComplexKeyHere_12121";
        //private const string SecurityKey = "1";
        private const string SecurityKey = "z20ds5898a4e5523bbce3ea1025a1916";

        //This method is used to convert the plain text to Encrypted/Un-Readable Text format.
        public string EncryptPlainTextToCipherText(string PlainText)
        {
            // Getting the bytes of Input String.
            byte[] toEncryptedArray = UTF8Encoding.UTF8.GetBytes(PlainText);

            //MD5CryptoServiceProvider objMD5CryptoService = new MD5CryptoServiceProvider();
            SHA256 objMD5CryptoService = SHA256.Create();
            //Gettting the bytes from the Security Key and Passing it to compute the Corresponding Hash Value.
            byte[] securityKeyArray = objMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SecurityKey));
            //De-allocatinng the memory after doing the Job.
            objMD5CryptoService.Clear();

            //var objTripleDESCryptoService = new TripleDESCryptoServiceProvider();
            //var objTripleDESCryptoService = new AesCryptoServiceProvider();
            var objTripleDESCryptoService = Aes.Create();
            //Assigning the Security key to the TripleDES Service Provider.
            objTripleDESCryptoService.Key = securityKeyArray;
            //Mode of the Crypto service is Electronic Code Book.
            objTripleDESCryptoService.Mode = CipherMode.ECB;
            //Padding Mode is PKCS7 if there is any extra byte is added.
            objTripleDESCryptoService.Padding = PaddingMode.PKCS7;


            var objCrytpoTransform = objTripleDESCryptoService.CreateEncryptor();
            //Transform the bytes array to resultArray
            byte[] resultArray = objCrytpoTransform.TransformFinalBlock(toEncryptedArray, 0, toEncryptedArray.Length);
            objTripleDESCryptoService.Clear();
            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        //This method is used to convert the Encrypted/Un-Readable Text back to readable  format.
        public string DecryptCipherTextToPlainText(string CipherText)
        {
            byte[] toEncryptArray = Convert.FromBase64String(CipherText);
            //MD5CryptoServiceProvider objMD5CryptoService = new MD5CryptoServiceProvider();
            SHA256 objMD5CryptoService = SHA256.Create();

            //Gettting the bytes from the Security Key and Passing it to compute the Corresponding Hash Value.
            byte[] securityKeyArray = objMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SecurityKey));
            objMD5CryptoService.Clear();

            //var objTripleDESCryptoService = new TripleDESCryptoServiceProvider();
            var objTripleDESCryptoService = Aes.Create();
            //Assigning the Security key to the TripleDES Service Provider.
            objTripleDESCryptoService.Key = securityKeyArray;
            //Mode of the Crypto service is Electronic Code Book.
            objTripleDESCryptoService.Mode = CipherMode.ECB;
            //Padding Mode is PKCS7 if there is any extra byte is added.
            objTripleDESCryptoService.Padding = PaddingMode.PKCS7;

            var objCrytpoTransform = objTripleDESCryptoService.CreateDecryptor();
            //Transform the bytes array to resultArray
            byte[] resultArray = objCrytpoTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);
            objTripleDESCryptoService.Clear();

            //Convert and return the decrypted data/byte into string format.
            return UTF8Encoding.UTF8.GetString(resultArray);
        }
    }
}
