using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using EncryptionAES;
namespace CBC
{
    internal class Program
    {



        static void Main(string[] args)
        {
            byte[] dataBlock = {
                0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20,
                0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F
            };
            byte[] Key = {
                0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79,
                0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
            };

            dataBlock = AES_Encryption.encrypt(dataBlock, Key);

            foreach (Byte b in dataBlock)
            {
                Console.Write($"0x{b:X2} ");
            }

            Console.ReadKey();


        }
    }
}
