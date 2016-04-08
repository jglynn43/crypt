package com.psi.crypt;

/**
 * A class to convert raw byte strings into six bit char strings.
 *
 * @author John Glynn
 * @version 1.2
 */
public class Base64Encoder {

    /**
     * Base64Encoder is not meant to implemented directly.
     */
    protected Base64Encoder() {
    }

    /**
     * Class method used to create strings of seven bit chars (RFC 1521) from an
     * array of bytes.
     *
     * @param raw The byte array to be represented with the string.
     * @return String containing a byte array encoded in Base64 format.
       *
     */
    public static String encode(byte[] raw) {
        StringBuilder encoded = new StringBuilder();
        for (int i = 0; i < raw.length; i += 3) {
            encoded.append(encodeBlock(raw, i));
        }

        return encoded.toString();
    }

    /**
     * Generate an encoded char array from the byte array at the given offset.
     *
     * @param raw The bytes used for input.
     * @param offset Integer offset from the beginning of the raw array.
     * @return An array of seven bit chars in the RFC 1521 format.
       *
     */
    protected static char[] encodeBlock(byte[] raw, int offset) {
        int block = 0;
        int slack = raw.length - offset - 1;
        int end = (slack >= 2) ? 2 : slack;

        for (int i = 0; i <= end; ++i) {
            byte b = raw[offset + i];
            int neuter = (b < 0) ? b + 256 : b;
            block += neuter << (8 * (2 - i));
        }

        char[] base64 = new char[4];
        for (int i = 0; i < 4; ++i) {
            int sixbit = (block >>> (6 * (3 - i))) & 0x3f;
            base64[i] = getRadix64Encoded(sixbit);
        }

        if (slack < 1) {
            base64[2] = '=';
        }
        if (slack < 2) {
            base64[3] = '=';
        }

        return base64;
    }

    /**
     * Return the base64 (RFC 1521) encoded character of the 7 bit integer.
     *
     * @param val Integer in range {0, ..., 63}
     * @return Encoded character.
     */
    protected static char getRadix64Encoded(int val) {
        if (val >= 0 && val <= 25) {
            return (char) (val + 'A');
        }
        if (val >= 26 && val <= 51) {
            return (char) ((val - 26) + 'a');
        }
        if (val >= 52 && val <= 61) {
            return (char) ((val - 52) + '0');
        }
        if (val == 62) {
            return '+';
        }
        if (val == 63) {
            return '/';
        }

        return (char) 0;
    }
}
