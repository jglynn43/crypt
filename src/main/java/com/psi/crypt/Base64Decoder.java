package com.psi.crypt;

/**
 * A class to convert six bit char strings into raw byte arrays.
 *
 * @author John Glynn
 * @version 1.2
 */
public class Base64Decoder {

    /**
     * Base64Decoder is not meant to implemented directly.
     */
    protected Base64Decoder() {
    }

    /**
     * Creates a byte array from a string of seven bit chars encoded in RFC 1521
     * format.
     *
     * @param base64 String containing chars representing a base64 encoding of
     * an array of bytes.
     * @return Decoded bytes.
       *
     */
    public static byte[] decode(String base64) {
        int pad = 0;
        for (int i = base64.length() - 1; base64.charAt(i) == '='; --i) {
            ++pad;
        }

        int length = base64.length() * 6 / 8 - pad;
        byte[] raw = new byte[length];

        int rawIndex = 0;
        for (int i = 0; i < base64.length(); i += 4) {
            int block = (getRadix64Value(base64.charAt(i)) << 18)
                    + (getRadix64Value(base64.charAt(i + 1)) << 12)
                    + (getRadix64Value(base64.charAt(i + 2)) << 6)
                    + (getRadix64Value(base64.charAt(i + 3)));

            for (int j = 0; j < 3 && rawIndex + j < raw.length; ++j) {
                raw[rawIndex + j] = (byte) ((block >> (8 * (2 - j))) & 0xff);
            }
            rawIndex += 3;
        }

        return raw;
    }

    /**
     * Return the base64 (RFC 1521) value of the encoded character. This
     * decoding scheme follows RFC 1521 format.
     *
     * @param c Encoded character
     * @return Integer value of encoded character
     */
    static int getRadix64Value(char c) {
        // Radix-64 de-coding

        if (c >= 'A' && c <= 'Z') {
            return c - 'A';
        }
        if (c >= 'a' && c <= 'z') {
            return c - 'a' + 26;
        }
        if (c >= '0' && c <= '9') {
            return c - '0' + 52;
        }
        if (c == '+') {
            return 62;
        }
        if (c == '/') {
            return 63;
        }
        if (c == '=') {
            return 0;
        }

        return -1;
    }
}
