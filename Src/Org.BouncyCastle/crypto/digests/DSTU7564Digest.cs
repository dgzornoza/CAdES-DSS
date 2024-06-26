﻿using Org.BouncyCastle.Crypto.Utilities;
//using Org.BouncyCastle.Utilities;


using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Digests
{
    /**
   * implementation of Ukrainian DSTU 7564 hash function
   */
    public class Dstu7564Digest : IDigest, IMemoable
    {
        private const int ROWS = 8;
        private const int BITS_IN_BYTE = 8;

        private const int NB_512 = 8;  //Number of 8-byte words in state for <=256-bit hash code.
        private const int NB_1024 = 16;  //Number of 8-byte words in state for <=512-bit hash code. 

        private const int NR_512 = 10;  //Number of rounds for 512-bit state.
        private const int NR_1024 = 14;  //Number of rounds for 1024-bit state.

        private const int STATE_BYTE_SIZE_512 = ROWS * NB_512;
        private const int STATE_BYTE_SIZE_1024 = ROWS * NB_1024;

        private int hashSize;
        private int blockSize;
        private int columns;
        private int rounds;
        private byte[] padded_;
        private byte[][] state_;
        private ulong inputLength;
        private int bufOff;
        private byte[] buf;

        public Dstu7564Digest(Dstu7564Digest digest)
        {
            CopyIn(digest);
        }

        private void CopyIn(Dstu7564Digest digest)
        {
            this.hashSize = digest.hashSize;
            this.blockSize = digest.blockSize;

            this.columns = digest.columns;
            this.rounds = digest.rounds;

            this.padded_ = Arrays.Clone(digest.padded_);
            this.state_ = new byte[digest.state_.Length][];

            for (int i = 0; i != this.state_.Length; i++)
            {
                this.state_[i] = Arrays.Clone(digest.state_[i]);
            }

            this.inputLength = digest.inputLength;
            this.bufOff = digest.bufOff;
            this.buf = Arrays.Clone(digest.buf);
        }

        public Dstu7564Digest(int hashSizeBits)
        {
            if (hashSizeBits == 256 || hashSizeBits == 384 || hashSizeBits == 512)
            {
                this.hashSize = hashSizeBits / 8;
            }
            else
            {
                throw new ArgumentException("Hash size is not recommended. Use 256 or 384 or 512 size");
            }

            if (hashSizeBits > 256)
            {
                this.blockSize = 1024 / 8;
                this.columns = NB_1024;
                this.rounds = NR_1024;
                this.state_ = new byte[STATE_BYTE_SIZE_1024][];
            }
            else
            {
                this.blockSize = 512 / 8;
                this.columns = NB_512;
                this.rounds = NR_512;
                this.state_ = new byte[STATE_BYTE_SIZE_512][];
            }

            for (int i = 0; i < state_.Length; i++)
            {
                this.state_[i] = new byte[columns];
            }

            this.state_[0][0] = (byte)state_.Length;

            this.hashSize = hashSizeBits / 8;

            this.padded_ = null;
            this.buf = new byte[blockSize];
        }

        public virtual string AlgorithmName
        {
            get { return "DSTU7564"; }
        }

        public virtual void BlockUpdate(byte[] input, int inOff, int length)
        {
            while (bufOff != 0 && length > 0)
            {
                Update(input[inOff++]);
                length--;
            }

            if (length > 0)
            {
                while (length > blockSize)
                {
                    ProcessBlock(input, inOff);
                    inOff += blockSize;
                    inputLength += (ulong)blockSize;
                    length -= blockSize;
                }

                while (length > 0)
                {
                    Update(input[inOff++]);
                    length--;
                }
            }
        }

        protected virtual byte[] Pad(byte[] input, int inOff, int length)
        {
            byte[] padded;
            if (blockSize - length < 13)         // terminator byte + 96 bits of length
            {
                padded = new byte[2 * blockSize];
            }
            else
            {
                padded = new byte[blockSize];
            }

            Array.Copy(input, inOff, padded, 0, length);
            padded[length] = 0x80;
            Pack.UInt64_To_LE(inputLength * 8, padded, padded.Length - 12);

            return padded;
        }

        protected virtual void ProcessBlock(byte[] input, int inOff)
        {
            byte[][] temp1 = new byte[columns][];
            byte[][] temp2 = new byte[columns][];

            int pos = inOff;
            for (int i = 0; i < columns; i++)
            {
                byte[] S = state_[i];
                byte[] T1 = temp1[i] = new byte[ROWS];
                byte[] T2 = temp2[i] = new byte[ROWS];

                for (int j = 0; j < ROWS; ++j)
                {
                    byte inVal = input[pos++];
                    T1[j] = (byte)(S[j] ^ inVal);
                    T2[j] = inVal;
                }
            }

            P(temp1);
            Q(temp2);

            for (int i = 0; i < columns; ++i)
            {
                byte[] S = state_[i], T1 = temp1[i], T2 = temp2[i];
                for (int j = 0; j < ROWS; ++j)
                {
                    S[j] ^= (byte)(T1[j] ^ T2[j]);
                }
            }
        }

        public virtual int DoFinal(byte[] output, int outOff)
        {
            padded_ = Pad(buf, 0, bufOff);

            int paddedLen = padded_.Length;
            int paddedOff = 0;

            while (paddedLen != 0)
            {
                ProcessBlock(padded_, paddedOff);
                paddedOff += blockSize;
                paddedLen -= blockSize;
            }

            byte[][] temp = new byte[STATE_BYTE_SIZE_1024][];
            for (int i = 0; i < state_.Length; i++)
            {
                temp[i] = new byte[ROWS];
                Array.Copy(state_[i], temp[i], ROWS);
            }

            P(temp);

            for (int i = 0; i < ROWS; ++i)
            {
                for (int j = 0; j < columns; ++j)
                {
                    state_[j][i] ^= temp[j][i];
                }
            }

            byte[] stateLine = new byte[ROWS * columns];
            int stateLineIndex = 0;
            for (int j = 0; j < columns; ++j)
            {
                for (int i = 0; i < ROWS; ++i)
                {
                    stateLine[stateLineIndex] = state_[j][i];
                    stateLineIndex++;
                }
            }

            Array.Copy(stateLine, stateLine.Length - hashSize, output, outOff, hashSize);

            Reset();

            return hashSize;
        }

        public virtual void Reset()
        {
            for (int bufferIndex = 0; bufferIndex < state_.Length; bufferIndex++)
            {
                state_[bufferIndex] = new byte[columns];
            }

            state_[0][0] = (byte)state_.Length;

            inputLength = 0;
            bufOff = 0;

            Arrays.Fill(buf, (byte)0);

            if (padded_ != null)
            {
                Arrays.Fill(padded_, (byte)0);
            }
        }

        public virtual int GetDigestSize()
        {
            return hashSize;
        }

        public virtual int GetByteLength()
        {
            return blockSize;
        }

        public virtual void Update(byte input)
        {
            buf[bufOff++] = input;
            if (bufOff == blockSize)
            {
                ProcessBlock(buf, 0);
                bufOff = 0;
            }
            inputLength++;
        }

        private void SubBytes(byte[][] state)
        {
            int i, j;
            for (i = 0; i < ROWS; ++i)
            {
                for (j = 0; j < columns; ++j)
                {
                    state[j][i] = sBoxes[i % 4][state[j][i]];
                }
            }
        }

        private void ShiftBytes(byte[][] state)
        {
            int i, j;
            byte[] temp = new byte[NB_1024];
            int shift = -1;
            for (i = 0; i < ROWS; ++i)
            {
                if ((i == ROWS - 1) && (columns == NB_1024))
                {
                    shift = 11;
                }
                else
                {
                    ++shift;
                }
                for (j = 0; j < columns; ++j)
                {
                    temp[(j + shift) % columns] = state[j][i];
                }
                for (j = 0; j < columns; ++j)
                {
                    state[j][i] = temp[j];
                }
            }
        }

        /* Pair-wise GF multiplication of 4 byte-pairs (at bits 0, 16, 32, 48 within x, y) */
        private static ulong MultiplyGFx4(ulong u, ulong v)
        {
            ulong r = u & ((v & 0x0001000100010001UL) * 0xFFFFUL);

            for (int i = 1; i < 8; ++i)
            {
                u <<= 1;
                v >>= 1;
                r ^= u & ((v & 0x0001000100010001L) * 0xFFFFL);
            }

            // REDUCTION_POLYNOMIAL = 0x011d; /* x^8 + x^4 + x^3 + x^2 + 1 */

            ulong hi = r & 0xFF00FF00FF00FF00UL;
            r ^= hi ^ (hi >> 4) ^ (hi >> 5) ^ (hi >> 6) ^ (hi >> 8);
            hi = r & 0x0F000F000F000F00UL;
            r ^= hi ^ (hi >> 4) ^ (hi >> 5) ^ (hi >> 6) ^ (hi >> 8);
            return r;
        }

        private void MixColumns(byte[][] state)
        {
            for (int col = 0; col < columns; ++col)
            {
                ulong colVal = Pack.LE_To_UInt64(state[col]);
                ulong colEven = colVal & 0x00FF00FF00FF00FFUL;
                ulong colOdd = (colVal >> 8) & 0x00FF00FF00FF00FFUL;

                //ulong rowMatrix = (mdsMatrix >> 8) | (mdsMatrix << 56);
                ulong rowMatrix = mdsMatrix;

                ulong result = 0;
                for (int row = 7; row >= 0; --row)
                {
                    ulong product = MultiplyGFx4(colEven, rowMatrix & 0x00FF00FF00FF00FFUL);

                    rowMatrix = (rowMatrix >> 8) | (rowMatrix << 56);

                    product ^= MultiplyGFx4(colOdd, rowMatrix & 0x00FF00FF00FF00FFUL);

                    product ^= (product >> 32);
                    product ^= (product >> 16);

                    result <<= 8;
                    result |= (product & 0xFFUL);
                }

                Pack.UInt64_To_LE(result, state[col]);
            }
        }

        private void AddRoundConstantP(byte[][] state, int round)
        {
            int i;
            for (i = 0; i < columns; ++i)
            {
                state[i][0] ^= (byte)((i * 0x10) ^ round);
            }
        }

        private void AddRoundConstantQ(byte[][] state, int round)
        {
            int j;
            UInt64[] s = new UInt64[columns];

            for (j = 0; j < columns; j++)
            {
                s[j] = Pack.LE_To_UInt64(state[j]);

                s[j] = s[j] + (0x00F0F0F0F0F0F0F3UL ^ ((((UInt64)(columns - j - 1) * 0x10UL) ^ (UInt64)round) << (7 * 8)));

                state[j] = Pack.UInt64_To_LE(s[j]);
            }
        }

        private void P(byte[][] state)
        {
            int i;
            for (i = 0; i < rounds; ++i)
            {
                AddRoundConstantP(state, i);
                SubBytes(state);
                ShiftBytes(state);
                MixColumns(state);
            }
        }

        private void Q(byte[][] state)
        {
            int i;
            for (i = 0; i < rounds; ++i)
            {
                AddRoundConstantQ(state, i);
                SubBytes(state);
                ShiftBytes(state);
                MixColumns(state);
            }
        }

        public virtual IMemoable Copy()
        {
            return new Dstu7564Digest(this);
        }

        public virtual void Reset(IMemoable other)
        {
            Dstu7564Digest d = (Dstu7564Digest)other;

            CopyIn(d);
        }

        //private const ulong mdsMatrix = 0x0407060801050101UL;
        private const ulong mdsMatrix = 0x0104070608010501UL;

        private static readonly byte[][] sBoxes = new byte[][]
        {
            new byte[] {
                0xa8, 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, 0xdf, 0x87, 0x95, 0x17, 0xf0, 0xd8, 0x09, 
                0x6d, 0xf3, 0x1d, 0xcb, 0xc9, 0x4d, 0x2c, 0xaf, 0x79, 0xe0, 0x97, 0xfd, 0x6f, 0x4b, 0x45, 0x39, 
                0x3e, 0xdd, 0xa3, 0x4f, 0xb4, 0xb6, 0x9a, 0x0e, 0x1f, 0xbf, 0x15, 0xe1, 0x49, 0xd2, 0x93, 0xc6, 
                0x92, 0x72, 0x9e, 0x61, 0xd1, 0x63, 0xfa, 0xee, 0xf4, 0x19, 0xd5, 0xad, 0x58, 0xa4, 0xbb, 0xa1, 
                0xdc, 0xf2, 0x83, 0x37, 0x42, 0xe4, 0x7a, 0x32, 0x9c, 0xcc, 0xab, 0x4a, 0x8f, 0x6e, 0x04, 0x27, 
                0x2e, 0xe7, 0xe2, 0x5a, 0x96, 0x16, 0x23, 0x2b, 0xc2, 0x65, 0x66, 0x0f, 0xbc, 0xa9, 0x47, 0x41, 
                0x34, 0x48, 0xfc, 0xb7, 0x6a, 0x88, 0xa5, 0x53, 0x86, 0xf9, 0x5b, 0xdb, 0x38, 0x7b, 0xc3, 0x1e, 
                0x22, 0x33, 0x24, 0x28, 0x36, 0xc7, 0xb2, 0x3b, 0x8e, 0x77, 0xba, 0xf5, 0x14, 0x9f, 0x08, 0x55, 
                0x9b, 0x4c, 0xfe, 0x60, 0x5c, 0xda, 0x18, 0x46, 0xcd, 0x7d, 0x21, 0xb0, 0x3f, 0x1b, 0x89, 0xff, 
                0xeb, 0x84, 0x69, 0x3a, 0x9d, 0xd7, 0xd3, 0x70, 0x67, 0x40, 0xb5, 0xde, 0x5d, 0x30, 0x91, 0xb1, 
                0x78, 0x11, 0x01, 0xe5, 0x00, 0x68, 0x98, 0xa0, 0xc5, 0x02, 0xa6, 0x74, 0x2d, 0x0b, 0xa2, 0x76, 
                0xb3, 0xbe, 0xce, 0xbd, 0xae, 0xe9, 0x8a, 0x31, 0x1c, 0xec, 0xf1, 0x99, 0x94, 0xaa, 0xf6, 0x26, 
                0x2f, 0xef, 0xe8, 0x8c, 0x35, 0x03, 0xd4, 0x7f, 0xfb, 0x05, 0xc1, 0x5e, 0x90, 0x20, 0x3d, 0x82, 
                0xf7, 0xea, 0x0a, 0x0d, 0x7e, 0xf8, 0x50, 0x1a, 0xc4, 0x07, 0x57, 0xb8, 0x3c, 0x62, 0xe3, 0xc8, 
                0xac, 0x52, 0x64, 0x10, 0xd0, 0xd9, 0x13, 0x0c, 0x12, 0x29, 0x51, 0xb9, 0xcf, 0xd6, 0x73, 0x8d, 
                0x81, 0x54, 0xc0, 0xed, 0x4e, 0x44, 0xa7, 0x2a, 0x85, 0x25, 0xe6, 0xca, 0x7c, 0x8b, 0x56, 0x80
            },

            new byte[] {
                0xce, 0xbb, 0xeb, 0x92, 0xea, 0xcb, 0x13, 0xc1, 0xe9, 0x3a, 0xd6, 0xb2, 0xd2, 0x90, 0x17, 0xf8, 
                0x42, 0x15, 0x56, 0xb4, 0x65, 0x1c, 0x88, 0x43, 0xc5, 0x5c, 0x36, 0xba, 0xf5, 0x57, 0x67, 0x8d, 
                0x31, 0xf6, 0x64, 0x58, 0x9e, 0xf4, 0x22, 0xaa, 0x75, 0x0f, 0x02, 0xb1, 0xdf, 0x6d, 0x73, 0x4d, 
                0x7c, 0x26, 0x2e, 0xf7, 0x08, 0x5d, 0x44, 0x3e, 0x9f, 0x14, 0xc8, 0xae, 0x54, 0x10, 0xd8, 0xbc, 
                0x1a, 0x6b, 0x69, 0xf3, 0xbd, 0x33, 0xab, 0xfa, 0xd1, 0x9b, 0x68, 0x4e, 0x16, 0x95, 0x91, 0xee, 
                0x4c, 0x63, 0x8e, 0x5b, 0xcc, 0x3c, 0x19, 0xa1, 0x81, 0x49, 0x7b, 0xd9, 0x6f, 0x37, 0x60, 0xca, 
                0xe7, 0x2b, 0x48, 0xfd, 0x96, 0x45, 0xfc, 0x41, 0x12, 0x0d, 0x79, 0xe5, 0x89, 0x8c, 0xe3, 0x20, 
                0x30, 0xdc, 0xb7, 0x6c, 0x4a, 0xb5, 0x3f, 0x97, 0xd4, 0x62, 0x2d, 0x06, 0xa4, 0xa5, 0x83, 0x5f, 
                0x2a, 0xda, 0xc9, 0x00, 0x7e, 0xa2, 0x55, 0xbf, 0x11, 0xd5, 0x9c, 0xcf, 0x0e, 0x0a, 0x3d, 0x51, 
                0x7d, 0x93, 0x1b, 0xfe, 0xc4, 0x47, 0x09, 0x86, 0x0b, 0x8f, 0x9d, 0x6a, 0x07, 0xb9, 0xb0, 0x98, 
                0x18, 0x32, 0x71, 0x4b, 0xef, 0x3b, 0x70, 0xa0, 0xe4, 0x40, 0xff, 0xc3, 0xa9, 0xe6, 0x78, 0xf9, 
                0x8b, 0x46, 0x80, 0x1e, 0x38, 0xe1, 0xb8, 0xa8, 0xe0, 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05, 
                0xf1, 0x6e, 0x94, 0x28, 0x9a, 0x84, 0xe8, 0xa3, 0x4f, 0x77, 0xd3, 0x85, 0xe2, 0x52, 0xf2, 0x82, 
                0x50, 0x7a, 0x2f, 0x74, 0x53, 0xb3, 0x61, 0xaf, 0x39, 0x35, 0xde, 0xcd, 0x1f, 0x99, 0xac, 0xad, 
                0x72, 0x2c, 0xdd, 0xd0, 0x87, 0xbe, 0x5e, 0xa6, 0xec, 0x04, 0xc6, 0x03, 0x34, 0xfb, 0xdb, 0x59, 
                0xb6, 0xc2, 0x01, 0xf0, 0x5a, 0xed, 0xa7, 0x66, 0x21, 0x7f, 0x8a, 0x27, 0xc7, 0xc0, 0x29, 0xd7
            },

            new byte[]{
                0x93, 0xd9, 0x9a, 0xb5, 0x98, 0x22, 0x45, 0xfc, 0xba, 0x6a, 0xdf, 0x02, 0x9f, 0xdc, 0x51, 0x59, 
                0x4a, 0x17, 0x2b, 0xc2, 0x94, 0xf4, 0xbb, 0xa3, 0x62, 0xe4, 0x71, 0xd4, 0xcd, 0x70, 0x16, 0xe1, 
                0x49, 0x3c, 0xc0, 0xd8, 0x5c, 0x9b, 0xad, 0x85, 0x53, 0xa1, 0x7a, 0xc8, 0x2d, 0xe0, 0xd1, 0x72, 
                0xa6, 0x2c, 0xc4, 0xe3, 0x76, 0x78, 0xb7, 0xb4, 0x09, 0x3b, 0x0e, 0x41, 0x4c, 0xde, 0xb2, 0x90, 
                0x25, 0xa5, 0xd7, 0x03, 0x11, 0x00, 0xc3, 0x2e, 0x92, 0xef, 0x4e, 0x12, 0x9d, 0x7d, 0xcb, 0x35, 
                0x10, 0xd5, 0x4f, 0x9e, 0x4d, 0xa9, 0x55, 0xc6, 0xd0, 0x7b, 0x18, 0x97, 0xd3, 0x36, 0xe6, 0x48, 
                0x56, 0x81, 0x8f, 0x77, 0xcc, 0x9c, 0xb9, 0xe2, 0xac, 0xb8, 0x2f, 0x15, 0xa4, 0x7c, 0xda, 0x38, 
                0x1e, 0x0b, 0x05, 0xd6, 0x14, 0x6e, 0x6c, 0x7e, 0x66, 0xfd, 0xb1, 0xe5, 0x60, 0xaf, 0x5e, 0x33, 
                0x87, 0xc9, 0xf0, 0x5d, 0x6d, 0x3f, 0x88, 0x8d, 0xc7, 0xf7, 0x1d, 0xe9, 0xec, 0xed, 0x80, 0x29, 
                0x27, 0xcf, 0x99, 0xa8, 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, 0x95, 0xd2, 0x3e, 0x5b, 0x40, 0x83, 
                0xb3, 0x69, 0x57, 0x1f, 0x07, 0x1c, 0x8a, 0xbc, 0x20, 0xeb, 0xce, 0x8e, 0xab, 0xee, 0x31, 0xa2, 
                0x73, 0xf9, 0xca, 0x3a, 0x1a, 0xfb, 0x0d, 0xc1, 0xfe, 0xfa, 0xf2, 0x6f, 0xbd, 0x96, 0xdd, 0x43, 
                0x52, 0xb6, 0x08, 0xf3, 0xae, 0xbe, 0x19, 0x89, 0x32, 0x26, 0xb0, 0xea, 0x4b, 0x64, 0x84, 0x82, 
                0x6b, 0xf5, 0x79, 0xbf, 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, 0xe8, 0x91, 
                0xf6, 0xff, 0x13, 0x58, 0xf1, 0x47, 0x0a, 0x7f, 0xc5, 0xa7, 0xe7, 0x61, 0x5a, 0x06, 0x46, 0x44, 
                0x42, 0x04, 0xa0, 0xdb, 0x39, 0x86, 0x54, 0xaa, 0x8c, 0x34, 0x21, 0x8b, 0xf8, 0x0c, 0x74, 0x67
            },

            new byte[]{
                0x68, 0x8d, 0xca, 0x4d, 0x73, 0x4b, 0x4e, 0x2a, 0xd4, 0x52, 0x26, 0xb3, 0x54, 0x1e, 0x19, 0x1f, 
                0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, 0x83, 0x13, 0x8a, 0xb7, 0xd5, 0x25, 0x79, 0xf5, 0xbd, 
                0x58, 0x2f, 0x0d, 0x02, 0xed, 0x51, 0x9e, 0x11, 0xf2, 0x3e, 0x55, 0x5e, 0xd1, 0x16, 0x3c, 0x66, 
                0x70, 0x5d, 0xf3, 0x45, 0x40, 0xcc, 0xe8, 0x94, 0x56, 0x08, 0xce, 0x1a, 0x3a, 0xd2, 0xe1, 0xdf, 
                0xb5, 0x38, 0x6e, 0x0e, 0xe5, 0xf4, 0xf9, 0x86, 0xe9, 0x4f, 0xd6, 0x85, 0x23, 0xcf, 0x32, 0x99, 
                0x31, 0x14, 0xae, 0xee, 0xc8, 0x48, 0xd3, 0x30, 0xa1, 0x92, 0x41, 0xb1, 0x18, 0xc4, 0x2c, 0x71, 
                0x72, 0x44, 0x15, 0xfd, 0x37, 0xbe, 0x5f, 0xaa, 0x9b, 0x88, 0xd8, 0xab, 0x89, 0x9c, 0xfa, 0x60, 
                0xea, 0xbc, 0x62, 0x0c, 0x24, 0xa6, 0xa8, 0xec, 0x67, 0x20, 0xdb, 0x7c, 0x28, 0xdd, 0xac, 0x5b, 
                0x34, 0x7e, 0x10, 0xf1, 0x7b, 0x8f, 0x63, 0xa0, 0x05, 0x9a, 0x43, 0x77, 0x21, 0xbf, 0x27, 0x09, 
                0xc3, 0x9f, 0xb6, 0xd7, 0x29, 0xc2, 0xeb, 0xc0, 0xa4, 0x8b, 0x8c, 0x1d, 0xfb, 0xff, 0xc1, 0xb2, 
                0x97, 0x2e, 0xf8, 0x65, 0xf6, 0x75, 0x07, 0x04, 0x49, 0x33, 0xe4, 0xd9, 0xb9, 0xd0, 0x42, 0xc7, 
                0x6c, 0x90, 0x00, 0x8e, 0x6f, 0x50, 0x01, 0xc5, 0xda, 0x47, 0x3f, 0xcd, 0x69, 0xa2, 0xe2, 0x7a, 
                0xa7, 0xc6, 0x93, 0x0f, 0x0a, 0x06, 0xe6, 0x2b, 0x96, 0xa3, 0x1c, 0xaf, 0x6a, 0x12, 0x84, 0x39, 
                0xe7, 0xb0, 0x82, 0xf7, 0xfe, 0x9d, 0x87, 0x5c, 0x81, 0x35, 0xde, 0xb4, 0xa5, 0xfc, 0x80, 0xef, 
                0xcb, 0xbb, 0x6b, 0x76, 0xba, 0x5a, 0x7d, 0x78, 0x0b, 0x95, 0xe3, 0xad, 0x74, 0x98, 0x3b, 0x36, 
                0x64, 0x6d, 0xdc, 0xf0, 0x59, 0xa9, 0x4c, 0x17, 0x7f, 0x91, 0xb8, 0xc9, 0x57, 0x1b, 0xe0, 0x61
            }
        };
    }
}
