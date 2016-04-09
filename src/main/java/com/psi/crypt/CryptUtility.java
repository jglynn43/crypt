package com.psi.crypt;

import java.math.BigInteger;

/**
 * A class used as namespace for common methods and data.
 *
 * @author John Glynn
 */
public class CryptUtility {

    /**
     * The 1024 bit Diffie-Hellman modulus values used by SKIP.
     */
    public static final byte[] SKIP_MODULUS_BYTES = {
        (byte) 0xF4, (byte) 0x88, (byte) 0xFD, (byte) 0x58,
        (byte) 0x4E, (byte) 0x49, (byte) 0xDB, (byte) 0xCD,
        (byte) 0x20, (byte) 0xB4, (byte) 0x9D, (byte) 0xE4,
        (byte) 0x91, (byte) 0x07, (byte) 0x36, (byte) 0x6B,
        (byte) 0x33, (byte) 0x6C, (byte) 0x38, (byte) 0x0D,
        (byte) 0x45, (byte) 0x1D, (byte) 0x0F, (byte) 0x7C,
        (byte) 0x88, (byte) 0xB3, (byte) 0x1C, (byte) 0x7C,
        (byte) 0x5B, (byte) 0x2D, (byte) 0x8E, (byte) 0xF6,
        (byte) 0xF3, (byte) 0xC9, (byte) 0x23, (byte) 0xC0,
        (byte) 0x43, (byte) 0xF0, (byte) 0xA5, (byte) 0x5B,
        (byte) 0x18, (byte) 0x8D, (byte) 0x8E, (byte) 0xBB,
        (byte) 0x55, (byte) 0x8C, (byte) 0xB8, (byte) 0x5D,
        (byte) 0x38, (byte) 0xD3, (byte) 0x34, (byte) 0xFD,
        (byte) 0x7C, (byte) 0x17, (byte) 0x57, (byte) 0x43,
        (byte) 0xA3, (byte) 0x1D, (byte) 0x18, (byte) 0x6C,
        (byte) 0xDE, (byte) 0x33, (byte) 0x21, (byte) 0x2C,
        (byte) 0xB5, (byte) 0x2A, (byte) 0xFF, (byte) 0x3C,
        (byte) 0xE1, (byte) 0xB1, (byte) 0x29, (byte) 0x40,
        (byte) 0x18, (byte) 0x11, (byte) 0x8D, (byte) 0x7C,
        (byte) 0x84, (byte) 0xA7, (byte) 0x0A, (byte) 0x72,
        (byte) 0xD6, (byte) 0x86, (byte) 0xC4, (byte) 0x03,
        (byte) 0x19, (byte) 0xC8, (byte) 0x07, (byte) 0x29,
        (byte) 0x7A, (byte) 0xCA, (byte) 0x95, (byte) 0x0C,
        (byte) 0xD9, (byte) 0x96, (byte) 0x9F, (byte) 0xAB,
        (byte) 0xD0, (byte) 0x0A, (byte) 0x50, (byte) 0x9B,
        (byte) 0x02, (byte) 0x46, (byte) 0xD3, (byte) 0x08,
        (byte) 0x3D, (byte) 0x66, (byte) 0xA4, (byte) 0x5D,
        (byte) 0x41, (byte) 0x9F, (byte) 0x9C, (byte) 0x7C,
        (byte) 0xBD, (byte) 0x89, (byte) 0x4B, (byte) 0x22,
        (byte) 0x19, (byte) 0x26, (byte) 0xBA, (byte) 0xAB,
        (byte) 0xA2, (byte) 0x5E, (byte) 0xC3, (byte) 0x55,
        (byte) 0xE9, (byte) 0x2F, (byte) 0x78, (byte) 0xC7
    };

    /**
     * The SKIP 1024 bit modulus.
     */
    public static final BigInteger SKIP_MODULUS
            = new BigInteger(1, SKIP_MODULUS_BYTES);

    /**
     * The base used with the SKIP 1024 bit modulus
     */
    public static final BigInteger SKIP_BASE = BigInteger.valueOf(2);

    /**
     * Commonly used bitmasks for bytes.
     */
    public static final byte[] bytemask = {
        (byte) 0x80, (byte) 0x40, (byte) 0x20, (byte) 0x10,
        (byte) 0x08, (byte) 0x04, (byte) 0x02, (byte) 0x01
    };

    /**
     * The hexadecimal chars.
     */
    public static final char[] hexChars = {'0', '1', '2', '3', '4', '5', '6',
        '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    /**
     * Commonly used bitmasks for integers.
     */
    public static final int[] intmask = {
        0x80000000, 0x40000000, 0x20000000, 0x10000000,
        0x08000000, 0x04000000, 0x02000000, 0x01000000,
        0x00800000, 0x00400000, 0x00200000, 0x00100000,
        0x00080000, 0x00040000, 0x00020000, 0x00010000,
        0x00008000, 0x00004000, 0x00002000, 0x00001000,
        0x00000800, 0x00000400, 0x00000200, 0x00000100,
        0x00000080, 0x00000040, 0x00000020, 0x00000010,
        0x00000008, 0x00000004, 0x00000002, 0x00000001
    };

    /**
     * The one-byte integers with odd parity
     */
    public static final int[] signedOddParity
            = {
                2, 4, 8, 14, 16, 22, 26,
                28, 32, 38, 42, 44, 50, 52,
                56, 62, 64, 70, 74, 76, 82,
                84, 88, 94, 98, 100, 104, 110,
                112, 118, 122, 124, -128, -122, -118,
                -116, -110, -108, -104, -98, -94, -92,
                -88, -82, -80, -74, -70, -68, -62,
                -60, -56, -50, -48, -42, -38, -36,
                -32, -26, -22, -20, -14, -12, -8, -2
            };

    /**
     * The one-byte integers with even parity
     */
    public static final int[] signedEvenParity
            = {
                0, 6, 10, 12, 18, 20, 24,
                30, 34, 36, 40, 46, 48, 54,
                58, 60, 66, 68, 72, 78, 80,
                86, 90, 92, 96, 102, 106, 108,
                114, 116, 120, 126, -126, -124, -120,
                -114, -112, -106, -102, -100, -96, -90,
                -86, -84, -78, -76, -72, -66, -64,
                -58, -54, -52, -46, -44, -40, -34,
                -30, -28, -24, -18, -16, -10, -6, -4
            };

    /**
     * Converts a byte array to hex string
     *
     * @param block Byte array to be output.
     * @return String representation of the byte array.
     */
    public static String toHexString(byte[] block) {
        StringBuilder buf = new StringBuilder();

        int len = block.length;

        for (int i = 0; i < len; i++) {
            byte2hex(block[i], buf);
            if (i < len - 1) {
                buf.append(":");
            }
        }
        return buf.toString();
    }

    /**
     * Set each byte in an array to zero. Somewhat equivalent to the C library
     * function bzero
     *
     * @param block Byte array to be zero'd
     */
    public static void clearMemory(byte[] block) {
        for (int i = 0; i < block.length; ++i) {
            block[i] = (byte) 0;
        }
    }

    /**
     * Returns the base64 (crypt) value of the encoded character. This decoding
     * scheme follows crypt(3C) format.
     *
     * @param c Encoded character
     * @return Integer value of encoded character
     */
    public static int asciiToBinary(char c) {
        return (c >= 'a' ? (c - 59) : c >= 'A' ? (c - 53) : c - '.');
    }

    /**
     * Returns the base64 (crypt) encoded character of the integer. This
     * encoding scheme follows crypt(3C) format.
     *
     * @param i Integer value in range {0, ..., 63}
     * @return Encoded character
     */
    public static char binaryToAscii(int i) {
        return (char) (i >= 38
                ? (i - 38 + 'a')
                : i >= 12 ? (i - 12 + 'A') : i + '.');
    }

    /**
     * Returns a long from a byte array starting at the given offset. This
     * method will convert at most eight bytes of the array and maybe less
     * depending on the array length and the given offset.
     *
     * @param array The byte[] from which the bytes are fetched
     * @param offset Integer offset into the array
     * @return A primitive long data type
     */
    public static long bytesToLong(byte[] array, int offset) {
        long l = 0;
        int length = array.length - offset;

        if (length >= 8) {
            for (int i = 0; i < 8; ++i) {
                l |= (long) (((long) array[offset + i] & 0xff) << 8 * (7 - i));
            }
        } else {
            for (int i = 0; i < length; ++i) {
                l |= (long) (((long) array[offset + i] & 0xff) << 8 * (length - 1 - i));
            }
        }

        return l;
    }

    /**
     * Returns an int from a byte array starting at the given offset. This
     * method will convert at most four bytes of the array and maybe less
     * depending on the array length and the given offset.
     *
     * @param array The byte[] from which the bytes are fetched
     * @param offset Integer offset into the array
     * @return A primitive integer data type
     */
    public static int bytesToInt(byte[] array, int offset) {
        int j = 0;
        int length = array.length - offset;

        if (length >= 4) {
            for (int i = 0; i < 4; ++i) {
                j |= ((int) array[offset + i] & 0xff) << 8 * (3 - i);
            }
        } else {
            for (int i = 0; i < length; ++i) {
                j |= ((int) array[offset + i] & 0xff) << 8 * (length - 1 - i);
            }
        }

        return j;
    }

    /**
     * Returns a byte array of eight bytes generated from a long type.
     *
     * @param l Long data
     * @return A byte[] containing the bytes which made up the long
     */
    public static byte[] longToBytes(long l) {
        byte[] bytes = new byte[8];

        for (int j = 0; j < 8; ++j) {
            bytes[j] = (byte) (l >>> 8 * (7 - j) & 0xff);
        }

        return bytes;
    }

    /**
     * Returns a byte array of four bytes generated from an integer type.
     *
     * @param i Integer data
     * @return A byte[] containing the bytes which made up the integer
     */
    public static byte[] intToBytes(int i) {
        byte[] bytes = new byte[4];

        for (int j = 0; j < 4; ++j) {
            bytes[j] = (byte) (i >>> 8 * (3 - j) & 0xff);
        }

        return bytes;
    }

    /**
     * CryptUtility is not meant to implemented directly.
     */
    private CryptUtility() {
    }

    /**
     * Converts a byte to hex digit and writes to the supplied buffer.
     *
     * @param b Byte containing hex number.
     * @param buf StringBuilder to contain the output.
     */
    private static void byte2hex(byte b, StringBuilder buf) {
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
}
