using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication1
{
    class Program
    {

        static void Main(string[] args)
        {
            const string passPhrase = "TESTING_KEY";
            var encrypted = Encrypt.EncryptString("Test Plain Password", passPhrase);
            Console.WriteLine(encrypted);
            Console.WriteLine(Encrypt.DecryptString(encrypted, passPhrase));
            Console.ReadLine();
        }
    }
    public static class Encrypt
    {
        private const string InitVector = "EqoAbZ72EA7VhuGf";
        private const int Keysize = 256;
        public static string EncryptString(string plainText, string passPhrase)
        {
            var initVectorBytes = Encoding.UTF8.GetBytes(InitVector);
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            var password = new PasswordDeriveBytes(passPhrase, null);
            var keyBytes = password.GetBytes(Keysize / 8);
            var symmetricKey = new RijndaelManaged { Mode = CipherMode.CBC };
            var encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);
            var memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
            cryptoStream.FlushFinalBlock();
            var cipherTextBytes = memoryStream.ToArray();
            memoryStream.Close();
            cryptoStream.Close();
            return Convert.ToBase64String(cipherTextBytes);
        }
        public static string DecryptString(string cipherText, string passPhrase)
        {
            try
            {
                var initVectorBytes = Encoding.UTF8.GetBytes(InitVector);
                var cipherTextBytes = Convert.FromBase64String(cipherText);
                var password = new PasswordDeriveBytes(passPhrase, null);
                var keyBytes = password.GetBytes(Keysize / 8);
                var symmetricKey = new RijndaelManaged { Mode = CipherMode.CBC };
                var decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
                var memoryStream = new MemoryStream(cipherTextBytes);
                var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                var plainTextBytes = new byte[cipherTextBytes.Length];
                var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                memoryStream.Close();
                cryptoStream.Close();
                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);

            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
