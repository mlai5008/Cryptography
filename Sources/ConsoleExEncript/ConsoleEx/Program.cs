// See https://aka.ms/new-console-template for more information


using ConsoleEx;
using System.Security.Cryptography;
using System.Text;
//********
////string hexValues = "4D";
//string hexValues = "AB";
////string hexValues = "5E";
//int value = Convert.ToInt32(hexValues, 16);
////int value2 = Convert.ToInt32(hexValues, 10);
//string stringValue = Char.ConvertFromUtf32(value);
//********

byte[] textBytes = Encoding.UTF8.GetBytes("Hello world!");
// after: 72 101 108 108 111 32 119 111 114 108 100 33 
string base64String = Convert.ToBase64String(textBytes);
// after: SGVsbG8gd29ybGQh

//************************

// before: SGVsbG8gd29ybGQh
byte[] base64EncodedBytes = Convert.FromBase64String(base64String);
// after: 119 111 114 108 100 33
string inputString = Encoding.UTF8.GetString(base64EncodedBytes);
// after: world!

Console.WriteLine(inputString);

//*************************************************

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

// или так 
//FileStream stream = new FileStream("C:\\test.txt", FileMode.Open, FileAccess.Read);
//DESCryptoServiceProvider cryptic = new DESCryptoServiceProvider();
//cryptic.Key = ASCIIEncoding.ASCII.GetBytes("ABCDEFGH");
//cryptic.IV = ASCIIEncoding.ASCII.GetBytes("ABCDEFGH");
//CryptoStream crStream = new CryptoStream(stream, cryptic.CreateDecryptor(), CryptoStreamMode.Read);
//string dataS;
//using (StreamReader reader = new StreamReader(crStream))
//    dataS = reader.ReadToEnd(); // вот это важно здесь

//**************************
//string fff = string.Empty;
//using (FileStream fileStream2 = new FileStream("C:\\test.txt", FileMode.Open, FileAccess.Read))
//using (RC2 crypt = RC2.Create())
//using (ICryptoTransform transform = crypt.CreateEncryptor())
//using (CryptoStream cs = new CryptoStream(fileStream2, transform, CryptoStreamMode.Write))
//using (StreamReader reader = new StreamReader(cs))
//    fff = reader.ReadToEnd();

//*****************************
//try
//{

//    string original = "Here is some data to encrypt!";

//    // Create a new instance of the AesCryptoServiceProvider
//    // class.  This generates a new key and initialization 
//    // vector (IV).
//    using (AesCryptoServiceProvider myAes = new AesCryptoServiceProvider())
//    {
//        Console.WriteLine("Original:   {0} \n", original);
//        // Encrypt the string to an array of bytes.
//        byte[] encrypted = EncryptStringToBytes_Aes(original, myAes.Key, myAes.IV);
//        Console.WriteLine("Encrypted:   {0} \n", System.Text.Encoding.UTF8.GetString(encrypted));
//        // Decrypt the bytes to a string.
//        string decrypted = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);

//        //Display the original data and the decrypted data.                   
//        Console.WriteLine("Decrypted Trip: {0}", decrypted);
//    }

//}
//catch (Exception e)
//{
//    Console.WriteLine("Error: {0}", e.Message);
//}

//********************************
//string encryptData = string.Empty;
//using (Aes algorithm = Aes.Create())
//using (ICryptoTransform encryptor = algorithm.CreateEncryptor())
//using (Stream f = new FileStream("encrypted.bin", FileMode.Open, FileAccess.Read))
//using (Stream cs = new CryptoStream(f, encryptor, CryptoStreamMode.Write))
//using (StreamReader reader = new StreamReader(cs))
//    encryptData = reader.ReadToEnd();

//byte[] originData = ASCIIEncoding.ASCII.GetBytes("Hello World!");
//string originData = "Hello World!";
////string encryptData = string.Empty;

//using (Aes algorithm = Aes.Create())
//{
//    //algorithm.Key = Encoding.UTF8.GetBytes("KEY");
//    algorithm.GenerateIV();
//    algorithm.GenerateKey();
//    algorithm.Padding = PaddingMode.Zeros;
//    //using (ICryptoTransform encryptor = algorithm.CreateEncryptor())
//    using (Stream f = new FileStream("encrypted.bin", FileMode.OpenOrCreate, FileAccess.ReadWrite))
//    using (Stream cs = new CryptoStream(f, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
//    using (StreamWriter writer = new StreamWriter(cs, Encoding.ASCII))
//        writer.Write(originData);
//}

////string encryptData = string.Empty;
////using (Aes algorithm = Aes.Create())
////using (ICryptoTransform encryptor = algorithm.CreateDecryptor())
////using (Stream f = new FileStream("encrypted.bin", FileMode.Open, FileAccess.Read))
////using (Stream cs = new CryptoStream(f, encryptor, CryptoStreamMode.Read))
////using (StreamReader reader = new StreamReader(cs))
////    encryptData = reader.ReadToEnd();


//string encryptData = string.Empty;
////using (Aes algorithm = Aes.Create())
//using (Aes algorithm = Aes.Create())
//{
//    //algorithm.Key = Encoding.UTF8.GetBytes("KEY");
//    //algorithm.Key = gener;

//    algorithm.Padding = PaddingMode.Zeros;
//    algorithm.GenerateIV();
//    algorithm.GenerateKey();

//    using (ICryptoTransform Decryptor = algorithm.CreateDecryptor())
//    using (Stream f = new FileStream("encrypted.bin", FileMode.Open, FileAccess.Read))
//    using (Stream cs = new CryptoStream(f, Decryptor, CryptoStreamMode.Read))
//    using (StreamReader reader = new StreamReader(cs, Encoding.ASCII))
//        encryptData = reader.ReadToEnd();

//    Console.WriteLine(encryptData);    
//}

//PasswordDeriveBytes
//**********************************
//**********************************
byte[] pwd = Encoding.ASCII.GetBytes("Hello World!");
byte[] ssf = null;
byte[] salt = CreateRandomSalt(7);
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
    // This example uses the SHA1 algorithm.
    // Due to collision problems with SHA1, Microsoft recommends SHA256 or better.
    tdes.Key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, tdes.IV);

    ICryptoTransform encryptor22 = tdes.CreateEncryptor();
    ssf = encryptor22.TransformFinalBlock(pwd, 0, pwd.Length);
    string encriptText = Encoding.ASCII.GetString(ssf);

    tdes.Clear();


}
catch
{

}
//byte[] pwd = Encoding.ASCII.GetBytes("Hello World!");
TripleDESCryptoServiceProvider tdes2 = new TripleDESCryptoServiceProvider();

try
{
    Console.WriteLine("Creating a key with PasswordDeriveBytes...");
    // Create a PasswordDeriveBytes object and then create
    // a TripleDES key from the password and salt.
    PasswordDeriveBytes pdb = new PasswordDeriveBytes(pwd, salt);


    // Create the key and set it to the Key property
    // of the TripleDESCryptoServiceProvider object.
    // This example uses the SHA1 algorithm.
    // Due to collision problems with SHA1, Microsoft recommends SHA256 or better.
    tdes2.Key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, tdes2.IV);

    ICryptoTransform decryptor = tdes2.CreateDecryptor();
    byte[] oiginBite = decryptor.TransformFinalBlock(ssf, 0, ssf.Length);
    string oiginText = Encoding.Default.GetString(oiginBite);
    string oiginText2 = Convert.ToBase64String(oiginBite);

    tdes2.Clear();

}
catch
{

}

//************************************
//***********************************
//****************************************
Test2 test2 = new Test2();
test2.Encrypt();
string f4f6f = test2.Decrypt();

//**************************
//****************************
//***********************

Test3 test3 = new Test3();
var encryptedString = test3.EncryptString("Hello world!");
Console.WriteLine($"encrypted string = {encryptedString}");

Console.WriteLine("--------------------------------------------------------------------------------------------");
var decryptedString = test3.DecryptString(encryptedString);
Console.WriteLine($"decrypted string = {decryptedString}");

//**********************************
//**********************************
//*****************************************
//Test4 test4 = new Test4();
//string enc = Convert.ToBase64String(test4.Encrypt(Encoding.UTF8.GetBytes("Hello world!")));
//string desc = Convert.ToBase64String(test4.Decrypt(Encoding.UTF8.GetBytes(enc)));

//***************
//**************
//*****************
string Original = "foo bar, this is an example";
Test5 test5 = new Test5();
var fff345 = test5.EncryptString(Original);
var deskr = test5.DecryptString(fff345);

Console.WriteLine(Original);
Console.WriteLine(Encoding.Default.GetString(fff345));
Console.WriteLine(deskr);

//*****************
//*****************
//*****************

Console.WriteLine();
var text = "This is my password to protect*!";
Test6 test6 = new Test6();
var encryptedText = test6.EncryptPlainTextToCipherText(text);
var decryptedText = test6.DecryptCipherTextToPlainText(encryptedText);

Console.WriteLine("Passed Text = " + text);
Console.WriteLine("EncryptedText = " + encryptedText);
Console.WriteLine("DecryptedText = " + decryptedText);

//*****************
//*****************
//*****************

Console.WriteLine();
//var text7 = "This is my password to protect*!";
//Test7 test7 = new Test7();
//string encrypted7 = test7.Encrypt(text7);
//var decrypted7 = test7.Decrypt(encryptedText);

//Console.WriteLine("Passed Text = " + text);
//Console.WriteLine("EncryptedText = " + encrypted7);
//Console.WriteLine("DecryptedText = " + decrypted7);

//*****************
//*****************
//*****************
Console.WriteLine();
var text8 = "This is my password to protect*!";
//var text8 = "Hi, world";
Test8 test8 = new Test8();
test8.Encrypt(text8);
string ddd8 = test8.Decrypt();
Console.WriteLine($"{nameof(Test8)}: {text8}");
Console.WriteLine($"{nameof(Test8)}: {ddd8}");

//*****************
//*****************
//*****************
//Console.WriteLine();
//var text9 = "This is my password to protect*!";
//Test9 test9 = new Test9();
//test9.Encrypt(text9);
//string ddd9 = test9.Decrypt();
//Console.WriteLine($"{nameof(Test9)}: {text9}");
//Console.WriteLine($"{nameof(Test9)}: {ddd9}");

//*****************
//*****************
//*****************
//Console.WriteLine();
//var text10 = "This is my password to protect*!";
//Test10 test10 = new Test10();
//string ffd10 = test10.Encrypt(text10);
//string ddd10 = test10.Decrypt(ffd10);
//Console.WriteLine($"{nameof(Test10)}: {text10}");
//Console.WriteLine($"{nameof(Test10)}: {ffd10}");
//Console.WriteLine($"{nameof(Test10)}: {ddd10}");

//*****************
//*****************
//*****************
Console.WriteLine();
string original = "Here is some data to encrypt**";
Test11 t11 = new Test11();
t11.EncryptDecrypt(original);
t11.CreateKeyEncryptDecrypt();
string cipherText = t11.Encrypt(original);
string decryptText = t11.Decrypt(cipherText);
Console.WriteLine(original);
Console.WriteLine(cipherText);
Console.WriteLine(decryptText);

//*****************
//*****************
//*****************
Console.WriteLine();
string original12 = string.Empty;
string fileName = string.Empty;
string password = string.Empty;
Test12 t12 = new Test12();
t12.EncryptToFile(original12, fileName, password);
string decryptText12 = t12.DecryptFromFile(fileName, password);
Console.WriteLine($"{nameof(Test12)}: {original12}");
Console.WriteLine($"{nameof(Test12)}: {decryptText12}");

Console.ReadLine();

static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
{
    // Check arguments.
    if (plainText == null || plainText.Length <= 0)
        throw new ArgumentNullException("plainText");
    if (Key == null || Key.Length <= 0)
        throw new ArgumentNullException("Key");
    if (IV == null || IV.Length <= 0)
        throw new ArgumentNullException("IV");
    byte[] encrypted;
    // Create an AesCryptoServiceProvider object
    // with the specified key and IV.
    using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
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

static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
{
    // Check arguments.
    if (cipherText == null || cipherText.Length <= 0)
        throw new ArgumentNullException("cipherText");
    if (Key == null || Key.Length <= 0)
        throw new ArgumentNullException("Key");
    if (IV == null || IV.Length <= 0)
        throw new ArgumentNullException("IV");

    // Declare the string used to hold
    // the decrypted text.
    string plaintext = null;

    // Create an AesCryptoServiceProvider object
    // with the specified key and IV.
    using (AesCryptoServiceProvider aesAlg = new AesCryptoServiceProvider())
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

static byte[] CreateRandomSalt(int length)
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
