package com.psi.crypt;

import java.security.AlgorithmParameters;

  /*
   * UFC-crypt: ultra fast crypt(3) implementation
   *
   * Copyright (C) 1991, 1992, 1993, 1996 Free Software Foundation, Inc.
   *
   * This library is free software; you can redistribute it and/or
   * modify it under the terms of the GNU Library General Public
   * License as published by the Free Software Foundation; either
   * version 2 of the License, or (at your option) any later version.
   *
   * This library is distributed in the hope that it will be useful,
   * but WITHOUT ANY WARRANTY; without even the implied warranty of
   * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   * Library General Public License for more details.
   *
   * You should have received a copy of the GNU Library General Public
   * License along with this library; see the file COPYING.LIB.  If not,
   * write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   * Boston, MA 02111-1307, USA.
   *
   * @(#)crypt.c  2.25 12/20/96
   *
   * Semiportable C version
   *
   * Ported to Java 4/2000.
   */

/**
 * Implementation of crypt(3C) based on GNU UFC-crypt.
 *
 * @author John Glynn
 */
class CryptImplementation {

    /**
     * Permutation done once on the 56 bit key derived from the original 8 byte
     * ASCII key.
     */
    private static final int[] pc1 = {
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
    };

    /**
     * The final permutation matrix.
     */
    private static final int[] final_perm = {
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    };

    /**
     * The sboxes for the DES algorithm.
     */
    private static final int[][][] sbox = {
        {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
        },
        {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
        },
        {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
        },
        {{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
        },
        {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
        },
        {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
        },
        {{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
        },
        {{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
        }
    };

    /**
     * The E expansion table which selects bits from the 32 bit intermediate
     * result.
     */
    private static final int[] esel = {
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    };

    /**
     * Permutation giving the key of the i' DES round.
     */
    private static final int[] pc2 = {
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    };

    /**
     * Permutation done on the result of sbox lookups.
     */
    private static final int[] perm32 = {
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    };

    /**
     * How much to rotate each 28 bit half of the pc1 permutated 56 bit key
     * before using pc2 to give the i' key
     */
    private static final int[] rots = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    /**
     * Additional bitmasks needed for permutations.
     */
    private static final int[] bitmask = {
        0x40000000, 0x20000000, 0x10000000, 0x08000000, 0x04000000, 0x02000000,
        0x01000000, 0x00800000, 0x00400000, 0x00200000, 0x00100000, 0x00080000,
        0x00004000, 0x00002000, 0x00001000, 0x00000800, 0x00000400, 0x00000200,
        0x00000100, 0x00000080, 0x00000040, 0x00000020, 0x00000010, 0x00000008
    };

    /**
     * Storage for the internal DES expanded key.
     */
    private final byte[] keysched;
    /**
     * Storage for the permuted sboxes.
     */
    private final byte[][] sb;
    /**
     * Two byte array which stores the raw salt bytes.
     */
    private byte[] saltBytes;
    /**
     * Stores the result of the digest prefixed with the salt.
     */
    private final char[] crypt_3_buf;
    /**
     * Two char array which stores the salt.
     */
    private final char[] current_salt;
    /**
     * Group of eight bytes which stores each bit of the saltbytes after
     * applying a bitmask.
     */
    private long current_saltbits;
    /**
     * Storage for data necessary to undo an E selection.
     */
    private final byte[] residue;

    /**
     * Perform pc1 permutation in the key schedule generation.
     *
     * The first index is the byte number in the 8 byte ASCII key. The second
     * index is the two 28 bits halves of the result. The third index selects
     * the 7 bits actually used of each byte.
     *
     * The result is kept with 28 bit per 32 bit with the 4 most significant
     * bits zero.
     */
    private final int[][][] do_pc1;

    /**
     * Perform pc2 permutation in the key schedule generation.
     *
     * The first index is the septet number in the two 28 bit intermediate
     * values. The second index is the septet values.
     *
     * Knowledge of the structure of the pc2 permutation is used.
     *
     * The result is kept with 28 bit per 32 bit with the 4 most significant
     * bits zero.
     */
    private final int[][] do_pc2;

    /**
     * Do 32 bit permutation and E selection
     *
     * The first index is the byte number in the 32 bit value to be permuted.
     * The second index is the value of this byte. The third index selects the
     * two 32 bit values.
     *
     * The table is used and generated internally in init to speed it up.
     */
    private final int[][][] eperm32tab;

    /**
     * Undo an extra e selection and do final permutation giving the DES result.
     *
     * Invoked 6 bit a time on two 48 bit values giving two 32 bit ints.
     */
    private final int[][][] efp;

    /**
     * No argument constructor allocates memory and calls init().
     */
    public CryptImplementation() {
        keysched = new byte[128];
        sb = new byte[4][32768];
        saltBytes = new byte[2];
        crypt_3_buf = new char[13];
        current_salt = new char[2];
        residue = new byte[16];

        do_pc1 = new int[8][2][128];
        do_pc2 = new int[8][128];
        eperm32tab = new int[4][256][2];
        efp = new int[16][64][2];

        init();
    }

    /**
     * Accessor method to get the result string.
     *
     * @return String made up of the base64 encoded characters.
     */
    public String getCrypt3Buffer() {
        return new String(crypt_3_buf);
    }

    /**
     * Perform 25 DES encryptions on the data.
     */
    void encrypt() {
        CryptUtility.clearMemory(residue);
        long l = 0;
        long r = 0;
        long s = 0;

        for (int itr = 25; itr > 0; --itr) {
            int offset = 0;
            long k = CryptUtility.bytesToLong(keysched, offset);
            for (int i = 8; i > 0; --i) {
                s = k ^ r;
                l ^= sbLong(s, 2, 0, 0xffff);
                l ^= sbLong(s, 2, 16, 0xffff);
                s >>>= 16;
                l ^= sbLong(s, 0, 16, 0xffff);
                s >>>= 16;
                l ^= sbLong(s, 0, 16, 0);
                s >>>= 16;

                offset += 8;
                k = CryptUtility.bytesToLong(keysched, offset);

                s = k ^ l;
                r ^= sbLong(s, 2, 0, 0xffff);
                r ^= sbLong(s, 2, 16, 0xffff);
                s >>>= 16;
                r ^= sbLong(s, 0, 16, 0xffff);
                s >>>= 16;
                r ^= sbLong(s, 0, 16, 0);
                s >>>= 16;

                offset += 8;
                k = CryptUtility.bytesToLong(keysched, offset);
            }
            s = l;
            l = r;
            r = s;
        }

        byte[] left = CryptUtility.longToBytes(l);
        byte[] right = CryptUtility.longToBytes(r);
        for (int i = 0; i < 8; ++i) {
            residue[i] = left[i];
            residue[i + 8] = right[i];
        }
        /*
          * Do final permutations
         */
        doFinalPerm();

        /*
          * And convert back to 6 bit ASCII
         */
        outputConversion();
    }

    /**
     * Initialize the keysched array.
     *
     * @param cryptKey An opaque container for the key (password bytes).
     */
    void makeKeyTable(CryptKey cryptKey) {
        int v1 = 0;
        int v2 = 0;
        byte[] key = cryptKey.getEncoded();

        for (int i = 8; i > 0; --i) {
            v1 |= do_pc1[8 - i][0][key[8 - i]];
            v2 |= do_pc1[8 - i][1][key[8 - i]];
        }

        long v = 0;
        int offset = 0;
        for (int i = 0; i < 16; ++i) {
            v1 = v1 << rots[i] | v1 >>> 28 - rots[i];

            offset = v1 >>> 21 & 0x7f;
            v = do_pc2[0][offset];
            offset = v1 >>> 14 & 0x7f;
            v |= do_pc2[1][offset];
            offset = v1 >>> 7 & 0x7f;
            v |= do_pc2[2][offset];
            offset = v1 & 0x7f;
            v |= do_pc2[3][offset];

            v <<= 32;
            v2 = v2 << rots[i] | v2 >>> 28 - rots[i];

            offset = v2 >>> 21 & 0x7f;
            v |= do_pc2[4][offset];
            offset = v2 >>> 14 & 0x7f;
            v |= do_pc2[5][offset];
            offset = v2 >>> 7 & 0x7f;
            v |= do_pc2[6][offset];
            offset = v2 & 0x7f;
            v |= do_pc2[7][offset];

            v |= 0x0000800000008000L;
            byte[] next = CryptUtility.longToBytes(v);
            for (int j = 0; j < 8; ++j) {
                keysched[i * 8 + j] = next[j];
            }
        }
    }

    /**
     * Take the encoded bytes of the salt and swap entries in the expansion
     * table according to the bits set in the salt.
     *
     * @param params Opaque container for the salt bits.
     */
    void setupSalt(AlgorithmParameters params) {
        try {
            saltBytes = params.getEncoded();
        } catch (java.io.IOException io) {
            System.out.println(io.getMessage());
            io.printStackTrace();
        }

        // Convert bytes to base64 char representation
        char[] s = new char[2];
        s[0] = CryptUtility.binaryToAscii(saltBytes[0]);
        s[1] = CryptUtility.binaryToAscii(saltBytes[1]);

        if (s[0] == current_salt[0] && s[1] == current_salt[1]) {
            return;
        }

        current_salt[0] = s[0];
        current_salt[1] = s[1];

        /*
          * This is the only crypt change to DES:
          * entries are swapped in the expansion table
          * according to the bits set in the salt.
         */
        long saltbits = 0;
        for (int i = 0; i < 2; ++i) {
            long c = CryptUtility.asciiToBinary(s[i]);
            for (int j = 0; j < 6; ++j) {
                if ((c >>> j & 0x1) != 0) {
                    saltbits |= (long) bitmask[6 * i + j] & 0xffffffff;
                }
            }
        }

        /*
          * Permute the sb table values
          * to reflect the changed e selection table
         */
        shuffle_sb(sb[0], current_saltbits ^ saltbits);
        shuffle_sb(sb[1], current_saltbits ^ saltbits);
        shuffle_sb(sb[2], current_saltbits ^ saltbits);
        shuffle_sb(sb[3], current_saltbits ^ saltbits);

        current_saltbits = saltbits;
    }

    /**
     * Populate the permutation arrays.
     */
    private void init() {
        /*
         * Create the do_pc1 table used to affect pc1 permutation
         * when generating keys
         */
        for (int i = 0; i < do_pc1.length; ++i) {
            for (int k = 0; k < do_pc1[i].length; ++k) {
                for (int l = 0; l < do_pc1[i][k].length; ++l) {
                    do_pc1[i][k][l] = 0;
                }
            }
        }

        int comes_from_bit = 0;
        int bit = 0;
        int j = 0;
        int mask1 = 0;
        int mask2 = 0;
        for (bit = 0; bit < 56; ++bit) {
            comes_from_bit = pc1[bit] - 1;
            mask1 = CryptUtility.bytemask[comes_from_bit % 8 + 1];
            mask2 = CryptUtility.intmask[bit % 28 + 4];
            for (j = 0; j < 128; ++j) {
                if ((j & mask1) != 0) {
                    do_pc1[comes_from_bit / 8][bit / 28][j] |= mask2;
                }
            }
        }

        /*
         * Create the do_pc2 table used to affect pc2 permutation when
         * generating keys
         */
        for (int i = 0; i < do_pc2.length; ++i) {
            for (int k = 0; k < do_pc2[i].length; ++k) {
                do_pc2[i][k] = 0;
            }
        }

        for (bit = 0; bit < 48; ++bit) {
            comes_from_bit = pc2[bit] - 1;
            mask1 = CryptUtility.bytemask[comes_from_bit % 7 + 1];
            mask2 = bitmask[bit % 24];
            for (j = 0; j < 128; ++j) {
                if ((j & mask1) != 0) {
                    do_pc2[comes_from_bit / 7][j] |= mask2;
                }
            }
        }

        /*
         * Now generate the table used to do combined 32 bit permutation 
         * and e expansion
         *
         * We use it because we have to permute 16384 32 bit
         * longs into 48 bits in order to initialize sb.
         *
         */
        for (int i = 0; i < eperm32tab.length; ++i) {
            for (int k = 0; k < eperm32tab[i].length; ++k) {
                for (int l = 0; l < eperm32tab[i][k].length; ++l) {
                    eperm32tab[i][k][l] = 0;
                }
            }
        }

        for (bit = 0; bit < 48; ++bit) {
            int comes_from = perm32[esel[bit] - 1] - 1;
            int mask3 = CryptUtility.bytemask[comes_from % 8];
            for (j = 256; j > 0;) {
                --j;
                if ((j & mask3) != 0) {
                    eperm32tab[comes_from / 8][j][bit / 24]
                            |= bitmask[bit % 24];
                }
            }
        }

        /*
         * Create an inverse matrix for esel telling where to plug out bits 
         * if undoing it
         */
        int[] e_inverse = new int[64];
        for (bit = 48; bit > 0;) {
            --bit;
            e_inverse[esel[bit] - 1] = bit;
            e_inverse[esel[bit] - 1 + 32] = bit + 48;
        }

        /*
         * create efp: the matrix used to undo the E expansion and effect 
         * final permutation
         */
        for (int i = 0; i < efp.length; ++i) {
            for (int k = 0; k < efp[i].length; ++k) {
                for (int l = 0; l < efp[i][k].length; ++l) {
                    efp[i][k][l] = 0;
                }
            }
        }

        for (bit = 0; bit < 64; ++bit) {
            /* See where bit i belongs in the two 32 bit long's */
            int o_long = bit / 32;
            /* 0..1  */
            int o_bit = bit % 32;
            /* 0..31 */

            /*
             * And find a bit in the e permutated value setting this bit.
             *
             * Note: the e selection may have selected the same bit several
             * times. By the initialization of e_inverse, we only look
             * for one specific instance.
             */
            int comes_from_f_bit = final_perm[bit] - 1;
            /* 0..63 */
            int comes_from_e_bit = e_inverse[comes_from_f_bit];
            /* 0..95 */
            int comes_from_word = comes_from_e_bit / 6;
            /* 0..15 */
            int bit_within_word = comes_from_e_bit % 6;
            /* 0..5  */

            int mask4 = CryptUtility.intmask[bit_within_word + 26];
            int mask5 = CryptUtility.intmask[o_bit];

            for (int word_value = 64; word_value > 0;) {
                --word_value;
                if ((word_value & mask4) != 0) {
                    efp[comes_from_word][word_value][o_long] |= mask5;
                }
            }
        }

        /*
         * Create the sb tables:
         *
         * For each 12 bit segment of an 48 bit intermediate
         * result, the sb table precomputes the two 4 bit
         * values of the sbox lookups done with the two 6
         * bit halves, shifts them to their proper place,
         * sends them through perm32 and finally E expands
         * them so that they are ready for the next
         * DES round.
         *
         */
        CryptUtility.clearMemory(sb[0]);
        CryptUtility.clearMemory(sb[1]);
        CryptUtility.clearMemory(sb[2]);
        CryptUtility.clearMemory(sb[3]);

        for (int sg = 0; sg < 4; ++sg) {
            for (int j1 = 0; j1 < 64; ++j1) {
                int s1 = sboxLookup(2 * sg, j1);
                for (int j2 = 0; j2 < 64; ++j2) {
                    int s2 = sboxLookup(2 * sg + 1, j2);
                    int to_permute = (s1 << 4 | s2) << 24 - 8 * sg;
                    int inx = j1 << 6 | j2;

                    long block
                            = (long) eperm32tab[0][to_permute >>> 24 & 0xff][0] << 32
                            | (long) eperm32tab[0][to_permute >>> 24 & 0xff][1];
                    block
                            |= (long) eperm32tab[1][to_permute >>> 16 & 0xff][0] << 32
                            | (long) eperm32tab[1][to_permute >>> 16 & 0xff][1];
                    block
                            |= (long) eperm32tab[2][to_permute >>> 8 & 0xff][0] << 32
                            | (long) eperm32tab[2][to_permute >>> 8 & 0xff][1];
                    block
                            |= (long) eperm32tab[3][to_permute & 0xff][0] << 32
                            | (long) eperm32tab[3][to_permute & 0xff][1];

                    byte[] temp = CryptUtility.longToBytes(block);
                    for (int k = 0; k < 8; ++k) {
                        sb[sg][inx * 8 + k] = temp[k];
                    }
                }
            }
        }
    }

    /**
     * Lookup a 6 bit value in an sbox.
     *
     * @param i The outer index.
     * @param s The integer used to calculate the inner two indices.
     * @return The integer value stored in the sbox.
     */
    private int sboxLookup(int i, int s) {
        return sbox[i][s >>> 4 & 0x2 | s & 0x1][s >>> 1 & 0xf];
    }

    /**
     * Calculate the offset into the sb array.
     *
     * @param l Long value used to generate the offset.
     * @param shift Number of bits l is right-shifted.
     * @param mask Bitmask applied to the result of the shift.
     * @return The calculated offset.
     */
    private int sbOffset(long l, int shift, int mask) {
        if (shift != 0 && mask != 0) {
            return (int) (l >>> shift & mask);
        } else if (shift != 0) {
            return (int) (l >>> shift);
        } else {
            return (int) (l & mask);
        }
    }

    /**
     * Returns the outer index into the sb array with the given index assuming a
     * flat memory space.
     *
     * @param offset The offset into the flat memory space obtained from
     * sbOffset.
     * @return The outer index.
     */
    private int sbRange(int offset) {
        if (offset < 0x8000) {
            return 0;
        } else if (offset < 0x10000) {
            return 1;
        } else if (offset < 0x18000) {
            return 2;
        } else if (offset < 0x20000) {
            return 3;
        } else {
            System.out.println("Invalid offset: " + offset);
            return -1;
        }
    }

    /**
     * Obtain a long value from eight bytes in the sb array.
     *
     * @param s A long value used to generate the offset.
     * @param index The starting outer index in the sb array.
     * @param shift Number of bits to shift s.
     * @param mask Bitmask to apply to shifted value of s.
     * @return Eight bytes of the sb array evaluated as a long
     */
    private long sbLong(long s, int index, int shift, int mask) {
        int offset = sbOffset(s, shift, mask);
        int range = sbRange(offset);
        offset -= range * 0x8000;

        if (offset <= (0x8000 - 8)) {
            return CryptUtility.bytesToLong(sb[index + range], offset);
        } else {
            long temp = 0;
            int k = 0;
            int bits = 0x8000 - offset;
            for (; k < bits; ++k) {
                temp |= ((long) sb[index + range][k + offset] & 0xff) << 8 * (7 - k);
            }
            for (int j = 0; j < (8 - bits); ++j) {
                temp |= ((long) sb[index + range + 1][j] & 0xff) << 8 * (7 - k++);
            }

            return temp;
        }
    }

    /**
     * Process the elements of the sb table permuting the bits swapped in the
     * expansion by the current salt.
     *
     * @param sbBytes The outer sb array being permuted.
     * @param saltbits A group of eight bytes used to permute the sb array.
     */
    private void shuffle_sb(byte[] sbBytes, long saltbits) {
        for (int i = 0; i < sbBytes.length; i += 8) {
            long y = CryptUtility.bytesToLong(sbBytes, i);
            long x = (y >>> 32 ^ y) & saltbits;
            y ^= x << 32 | x;

            // Put the new long back in the byte[]
            byte[] shuffle = CryptUtility.longToBytes(y);

            for (int j = 0; j < 8; ++j) {
                sbBytes[i + j] = shuffle[j];
            }
        }
    }

    /**
     * Undo an extra E selection and do final permutations
     */
    private void doFinalPerm() {
        int v1 = 0;
        int v2 = 0;
        int l1 = CryptUtility.bytesToInt(residue, 0);
        int l2 = CryptUtility.bytesToInt(residue, 4);
        int r1 = CryptUtility.bytesToInt(residue, 8);
        int r2 = CryptUtility.bytesToInt(residue, 12);

        int x = (int) ((long) ((l1 ^ l2) & 0xffffffff) & current_saltbits);
        l1 ^= x;
        l2 ^= x;

        x = (int) ((long) ((r1 ^ r2) & 0xffffffff) & current_saltbits);
        r1 ^= x;
        r2 ^= x;

        l1 >>>= 3;
        l2 >>>= 3;
        r1 >>>= 3;
        r2 >>>= 3;

        v1 |= efp[15][r2 & 0x3f][0];
        v2 |= efp[15][r2 & 0x3f][1];
        v1 |= efp[14][(r2 >>>= 6) & 0x3f][0];
        v2 |= efp[14][r2 & 0x3f][1];
        v1 |= efp[13][(r2 >>>= 10) & 0x3f][0];
        v2 |= efp[13][r2 & 0x3f][1];
        v1 |= efp[12][(r2 >>>= 6) & 0x3f][0];
        v2 |= efp[12][r2 & 0x3f][1];

        v1 |= efp[11][r1 & 0x3f][0];
        v2 |= efp[11][r1 & 0x3f][1];
        v1 |= efp[10][(r1 >>>= 6) & 0x3f][0];
        v2 |= efp[10][r1 & 0x3f][1];
        v1 |= efp[9][(r1 >>>= 10) & 0x3f][0];
        v2 |= efp[9][r1 & 0x3f][1];
        v1 |= efp[8][(r1 >>>= 6) & 0x3f][0];
        v2 |= efp[8][r1 & 0x3f][1];

        v1 |= efp[7][l2 & 0x3f][0];
        v2 |= efp[7][l2 & 0x3f][1];
        v1 |= efp[6][(l2 >>>= 6) & 0x3f][0];
        v2 |= efp[6][l2 & 0x3f][1];
        v1 |= efp[5][(l2 >>>= 10) & 0x3f][0];
        v2 |= efp[5][l2 & 0x3f][1];
        v1 |= efp[4][(l2 >>>= 6) & 0x3f][0];
        v2 |= efp[4][l2 & 0x3f][1];

        v1 |= efp[3][l1 & 0x3f][0];
        v2 |= efp[3][l1 & 0x3f][1];
        v1 |= efp[2][(l1 >>>= 6) & 0x3f][0];
        v2 |= efp[2][l1 & 0x3f][1];
        v1 |= efp[1][(l1 >>>= 10) & 0x3f][0];
        v2 |= efp[1][l1 & 0x3f][1];
        v1 |= efp[0][(l1 >>>= 6) & 0x3f][0];
        v2 |= efp[0][l1 & 0x3f][1];

        byte[] first = CryptUtility.intToBytes(v1);
        byte[] second = CryptUtility.intToBytes(v2);

        for (int i = 0; i < 4; ++i) {
            residue[i] = first[i];
            residue[i + 4] = second[i];
        }
    }

    /**
     * Convert from 64 bit to 11 bit ASCII prefixing with the salt.
     */
    private void outputConversion() {
        int v1 = CryptUtility.bytesToInt(residue, 0);
        int v2 = CryptUtility.bytesToInt(residue, 4);

        crypt_3_buf[0] = current_salt[0];
        crypt_3_buf[1] = current_salt[1];

        int shf = 0;
        for (int i = 0; i < 5; ++i) {
            shf = 26 - 6 * i;
            crypt_3_buf[i + 2] = CryptUtility.binaryToAscii(v1 >>> shf & 0x3f);
        }

        int s = (v2 & 0xf) << 2;
        v2 = v2 >>> 2 | (v1 & 0x3) << 30;

        for (int i = 5; i < 10; ++i) {
            shf = 56 - 6 * i;
            crypt_3_buf[i + 2] = CryptUtility.binaryToAscii(v2 >>> shf & 0x3f);
        }

        crypt_3_buf[12] = CryptUtility.binaryToAscii(s);
    }
}
