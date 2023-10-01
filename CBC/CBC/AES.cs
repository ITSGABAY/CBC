using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AdvancedEncryptionStandard
{
    internal class AES
    {
        public static byte[] Encrypt(byte[] dataBlock, byte[] Key)
        {
            byte[,] keys = keyExpansion(Key);
            Byte[] cKey = new Byte[16];
            dataBlock = addRoundKey(dataBlock, Key);

            for (int i = 1; i <= 9; i++)
            {
                for (int j = 0; j < 16; j++)
                {
                    cKey[j] = keys[i, j];
                }
                dataBlock = subBytes(dataBlock);
                dataBlock = shiftRows(dataBlock);
                dataBlock = mixColumns(dataBlock);
                dataBlock = addRoundKey(dataBlock, cKey);
            }
            for (int j = 1; j < 16; j++)
            {
                cKey[j] = keys[10, j];
            }
            for (int j = 0; j < 16; j++)
            {
                cKey[j] = keys[10, j];
            }
            dataBlock = subBytes(dataBlock);
            dataBlock = shiftRows(dataBlock);
            dataBlock = addRoundKey(dataBlock, cKey);
            return dataBlock;
        }
        public static byte[] Decrypt(byte[] dataBlock, byte[] Key)
        {



            byte[,] keys = keyExpansion(Key);
            Byte[] cKey = new Byte[16];
            for (int j = 0; j < 16; j++)
            {
                cKey[j] = keys[10, j];
            }
            dataBlock = addRoundKey(dataBlock, cKey);

            for (int i = 1; i <= 9; i++)
            {
                dataBlock = inverseShiftRows(dataBlock);
                dataBlock = InvSubBytes(dataBlock);
                for (int j = 0; j < 16; j++)
                {
                    cKey[j] = keys[10 - i, j];
                }

                dataBlock = addRoundKey(dataBlock, cKey);
                dataBlock = InvmixColumns(dataBlock);
            }
            dataBlock = inverseShiftRows(dataBlock);
            dataBlock = InvSubBytes(dataBlock);
            dataBlock = addRoundKey(dataBlock, Key);

            return dataBlock;
        }

        public static Byte[,] keyExpansion(Byte[] key)
        {
            Byte[,] keys = new Byte[11, 16];
            for (int j = 0; j < 16; j++)
            {
                keys[0, j] = key[j];
            }
            for (int i = 1; i < 11; i++)
            {
                Byte[] prevKey = new Byte[16];
                for (int j = 0; j < 16; j++)
                {
                    prevKey[j] = keys[i - 1, j];
                }
                Byte[] newKey = createKey(prevKey, i);

                for (int j = 0; j < 16; j++)
                {
                    keys[i, j] = newKey[j];
                }

            }
            return keys;
        }
        public static Byte[] createKey(Byte[] key, int round)
        {
            Byte[] newKey = new Byte[16];

            Byte[] word0 = key.Take(4).ToArray();
            Byte[] word1 = key.Skip(4).Take(4).ToArray();
            Byte[] word2 = key.Skip(8).Take(4).ToArray();
            Byte[] word3 = key.Skip(12).Take(4).ToArray();

            Byte[] word3gFunc = gFunc(word3, round);

            for (int i = 0; i < 4; i++)
            {
                newKey[i] = (Byte)(word3gFunc[i] ^ word0[i]);
                newKey[i + 4] = (Byte)(newKey[i] ^ word1[i]);
                newKey[i + 8] = (Byte)(newKey[i + 4] ^ word2[i]);
                newKey[i + 12] = (Byte)(newKey[i + 8] ^ word3[i]);
            }

            return newKey;
        }
        public static Byte[] addRoundKey(Byte[] block, Byte[] key) 
        {
            Byte[] newBlock = new Byte[16];
            for (int i = 0; i < 16; i++)
            {
                newBlock[i] = (Byte)(block[i] ^ key[i]);
            }
            return newBlock;
        }
        private static Byte[] gFunc(Byte[] bytes, int round)
        {
            Byte[] tempBytes = { bytes[1], bytes[2], bytes[3], bytes[0] };
            tempBytes = subBytes(tempBytes);
            byte rci = (Byte)(1 * Math.Pow(2, round - 1));
            tempBytes[0] = (Byte)(tempBytes[0] ^ Rcon[round]);

            return tempBytes;
        }

        public static Byte[] subBytes(Byte[] block) //good
        {
            Byte[] newBlock = new Byte[block.Length];
            for (int i = 0; i < block.Length; i++)
            {
                newBlock[i] = sBox[block[i] >> 4, block[i] & 0x0F];            //הזזה 4 ביטים ימינה והזזה 4 שמאלה.

            }

            return newBlock;

        }
        private static Byte[] InvSubBytes(Byte[] block) //good
        {
            Byte[] newBlock = new Byte[block.Length];
            for (int i = 0; i < block.Length; i++)
            {
                newBlock[i] = invSBox[block[i] >> 4, block[i] & 0x0F];            //הזזה 4 ביטים ימינה והזזה 4 שמאלה.

            }

            return newBlock;

        }
        private static byte[] shiftRows(byte[] dataBlock)
    {
        byte[] newBlock = new byte[16];
        byte[] row2 = new byte[4];
        byte[] row3 = new byte[4];
        byte[] row4 = new byte[4];

        for (int i = 0; i < 4; i++)
        {
            int currentIndex = i - 1;
            if (currentIndex < 0)
            {
                currentIndex = 4 + currentIndex;
            }
            row2[currentIndex] = dataBlock[i * 4 + 1];
            currentIndex = i - 2;
            if (currentIndex < 0)
            {
                currentIndex = 4 + currentIndex;
            }
            row3[currentIndex] = dataBlock[i * 4 + 2];
            currentIndex = i - 3;
            if (currentIndex < 0)
            {
                currentIndex = 4 + currentIndex;
            }
            row4[currentIndex] = dataBlock[i * 4 + 3];
        }

        for (int i = 0; i < 4; i++)
        {
            newBlock[4 * i] = dataBlock[4 * i];
            newBlock[(4 * i) + 1] = row2[i];
            newBlock[(4 * i) + 2] = row3[i];
            newBlock[(4 * i) + 3] = row4[i];
        }


        return newBlock;



    }
        public static byte[] inverseShiftRows(byte[] dataBlock)
        {
            byte[] newBlock = new byte[16];
            byte[] row2 = new byte[4];
            byte[] row3 = new byte[4];
            byte[] row4 = new byte[4];

            for (int i = 0; i < 4; i++)
            {
                int currentIndex = i + 1;
                if (currentIndex > 3)
                {
                    currentIndex = currentIndex - 4;
                }
                row2[currentIndex] = dataBlock[i * 4 + 1];
                currentIndex = i + 2;
                if (currentIndex > 3)
                {
                    currentIndex = currentIndex - 4;
                }
                row3[currentIndex] = dataBlock[i * 4 + 2];
                currentIndex = i + 3;
                if (currentIndex > 3)
                {
                    currentIndex = currentIndex - 4;
                }
                row4[currentIndex] = dataBlock[i * 4 + 3];
            }

            for (int i = 0; i < 4; i++)
            {
                newBlock[4 * i] = dataBlock[4 * i];
                newBlock[(4 * i) + 1] = row2[i];
                newBlock[(4 * i) + 2] = row3[i];
                newBlock[(4 * i) + 3] = row4[i];
            }


            return newBlock;


        }

        private static byte[] mixColumns(byte[] block)
    {
        byte[] newBlock = new byte[16];
        for (int i = 0; i < 4; i++)
        {
            for (int j = i * 4; j <= i * 4 + 3; j++)
            {
                newBlock[j] = (byte)(GFMultiply(mixColumnsMatrix[j % 4, 0], block[i * 4]) ^
                                GFMultiply(mixColumnsMatrix[j % 4, 1], block[i * 4 + 1]) ^
                                GFMultiply(mixColumnsMatrix[j % 4, 2], block[i * 4 + 2]) ^
                                GFMultiply(mixColumnsMatrix[j % 4, 3], block[i * 4 + 3]));
            }
        }
        return newBlock;
    }
        private static byte[] InvmixColumns(byte[] block)
        {
            byte[] newBlock = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = i * 4; j <= i * 4 + 3; j++)
                {
                    newBlock[j] = (byte)(GFMultiply(invMixColumnsMatrix[j % 4, 0], block[i * 4]) ^
                                    GFMultiply(invMixColumnsMatrix[j % 4, 1], block[i * 4 + 1]) ^
                                    GFMultiply(invMixColumnsMatrix[j % 4, 2], block[i * 4 + 2]) ^
                                    GFMultiply(invMixColumnsMatrix[j % 4, 3], block[i * 4 + 3]));
                }
            }
            return newBlock;
        }
        private static byte GFMultiply(byte a, byte b)
        {
            byte p = 0;
            byte high_bit_mask = 0x80;
            byte high_bit_set;
            byte modulo = 0x1B;

            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0)
                {
                    p ^= a;
                }

                high_bit_set = (byte)(a & high_bit_mask);
                a <<= 1;

                if (high_bit_set != 0)
                {
                    a ^= modulo;
                }

                b >>= 1;
            }

            return p;
        }

        public static readonly byte[,] sBox =
{
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };
        public static byte[,] invSBox = new byte[16, 16] {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};
        public static readonly byte[,] mixColumnsMatrix =
    {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };
        public static readonly byte[,] invMixColumnsMatrix =
{
    {0x0e, 0x0b, 0x0d, 0x09},
    {0x09, 0x0e, 0x0b, 0x0d},
    {0x0d, 0x09, 0x0e, 0x0b},
    {0x0b, 0x0d, 0x09, 0x0e}
};
        public static readonly byte[] Rcon = new byte[11]
{
            0x00,
            0x01,
            0x02,
            0x04,
            0x08,
            0x10,
            0x20,
            0x40,
            0x80,
            0x1B,
            0x36
};
    }
}
