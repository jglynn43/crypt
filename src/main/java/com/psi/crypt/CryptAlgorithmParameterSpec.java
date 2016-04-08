package com.psi.crypt;

import java.security.spec.AlgorithmParameterSpec;

/**
 * Transparent container for Crypt algorithm parameters. The only parameter used
 * in the algorithm is the 2 char array commonly known as the "salt".
 *
 * @author John Glynn
 */
public class CryptAlgorithmParameterSpec implements AlgorithmParameterSpec {

    /**
     * Byte[] used to store "salt" for crypt.
     */
    private final byte[] salt;

    /**
     * Construct a specification using a char[]. The array parameter must be at
     * least 2 long or ArrayIndexOutOfBoundsException will be thrown.
     *
     * @param chars The array of characters input to the salt. These must be in
     * the crypt(3C)-base64 format.
     * @exception ArrayIndexOutOfBoundsException Thrown when using a char[]
     * parameter which is too short.
     */
    public CryptAlgorithmParameterSpec(char[] chars) {
        salt = new byte[2];

        salt[0] = (byte) CryptUtility.asciiToBinary(chars[0]);
        salt[1] = (byte) CryptUtility.asciiToBinary(chars[1]);
    }

    /**
     * Construct a specification using a byte[]. The array parameter must be at
     * least 2 long or ArrayIndexOutOfBoundsException will be thrown.
     *
     * @param sl The array of bytes input to the salt. These must have been
     * obtained from a char[] or String in the crypt(3C)-base64 format.
     * @exception ArrayIndexOutOfBoundsException Thrown when using a byte[]
     * parameter which is too short.
     */
    public CryptAlgorithmParameterSpec(byte[] sl) {
        salt = new byte[2];

        salt[0] = sl[0];
        salt[1] = sl[1];
    }

    /**
     * Accessor method to get "salt".
     *
     * @return Byte[] containing two byte salt value.
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Accessor method to get "salt".
     *
     * @return Byte[] containing two byte salt value.
     */
    public byte[] getEncoded() {
        return getSalt();
    }
}
