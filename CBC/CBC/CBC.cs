using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipherBlockChaining
{
    internal class CBC
    {
        public static byte[,] Decrypt(byte[,] blocks, byte[] key, byte[] IV)
        {
            byte[] prevBlock = new byte[16];
            byte[] newBlock = new byte[16];
            byte[,] newBlocks = new byte[blocks.GetLength(0), blocks.GetLength(1)];
            byte[] currentBlock = new byte[16];
            for (int i = blocks.GetLength(0) - 1; i >= 0; i--)
            {
                for (int j = 0; j < 16; j++)
                {
                    currentBlock[j] = blocks[i, j];
                }
                currentBlock = AES.Decrypt(currentBlock, key);
                if (i == 0)
                {
                    prevBlock = IV;
                }
                else
                {
                    for (int j = 0; j < 16; j++)
                    {
                        prevBlock[j] = blocks[i - 1, j];
                    }
                }
                currentBlock = xorArray(prevBlock, currentBlock);
                for (int j = 0; j < 16; j++)
                {
                    newBlocks[i, j] = currentBlock[j];
                }
            }
            return newBlocks;
        }

        public static byte[,] Encrypt(byte[,] blocks, byte[] key, byte[] IV)
        {
            byte[] prevBlock = IV;
            byte[] newBlock = new byte[16];
            byte[,] newBlocks = new byte[blocks.GetLength(0), blocks.GetLength(1)];
            byte[] currentBlock = new byte[16];
            for (int i = 0; i < blocks.GetLength(0); i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    currentBlock[j] = blocks[i, j];
                }
                newBlock = AES.Encrypt(xorArray(prevBlock, currentBlock), key);
                for (int j = 0; j < 16; j++)
                {
                    newBlocks[i, j] = newBlock[j];
                }
                prevBlock = newBlock;
            }
            return newBlocks;
        }

    }
}
