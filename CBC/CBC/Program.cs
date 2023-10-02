using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AdvancedEncryptionStandard;
namespace CBC
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            byte[] Block1 = {
    0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20,
    0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F
};
            byte[] Block2 = {
    0x54, 0x77, 0x6F, 0x20, 0x4F, 0x6E, 0x65, 0x20,
    0x4E, 0x69, 0x6E, 0x65, 0x20, 0x54, 0x77, 0x6F
};
            byte[] Key = {
    0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79,
    0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
};
            byte[] IV = {
    0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79,
    0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75
};
            byte[,] Block3 = stringToBlocks("hello my bro icacasdasdasdas");

            byte[,] newBlocks = encrypt(Block3, Key, IV);

            byte[,] block3 = decrypt(newBlocks, Key, IV);


            foreach (Byte b in newBlocks)
            {
                Console.Write($"{b:X2}");

            }

            

            Console.ReadKey();



        }

        

        public static byte[,] stringToBlocks(string str)
        {
            byte[,] blocks = new byte[(str.Length-1) / 16 +1, 16];
            int countForPadding = (16 * (str.Length / 16 + 1)) - str.Length;
            for(int i=0; i<str.Length; i++)
            {
                blocks[i/16 , i%16] = Convert.ToByte(str[i]);
            }
            for (int i = 0; i <16; i++)
            {
                if (blocks[(str.Length-1) / 16, i] == 0x00)
                {
                    
                    blocks[str.Length / 16 , i] = Convert.ToByte(countForPadding);
                }
            }
            return blocks;
        }

        public static byte[] xorArray(byte[] a1, byte[] a2)
        {
            byte[] newArray = new byte[a1.Length];
            for(int i=0; i<a1.Length;i++)
            {
                newArray[i] = (byte)(a1[i] ^ a2[i]);
            }
            return newArray;

        }


    }
}
