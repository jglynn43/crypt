package com.psi.crypt;

import javax.crypto.SecretKey;

/**
 * Opaque representation of the key used in the crypt(3C) algorithm.
 *
 * @author John Glynn
 * @version 1.2
 */
public class CryptKey implements SecretKey {

    /**
     * Internal storage for the key.
     *
     * @serial
     */
    private final byte[] keyBytes;

    /**
     * Creates a key from a specification.
     *
     * @param spec A transparent representation of the key bytes.
     */
    public CryptKey(CryptKeySpec spec) {
        keyBytes = spec.getEncoded();
    }

    /**
     * Creates a key from a raw byte array.
     *
     * @param bt The byte array used to construct the key. This must be in
     * <code>"RAW"</code> format.
     */
    public CryptKey(byte[] bt) {
        keyBytes = bt;
    }

    /**
     * Accessor method to get the name of the algorithm.
     *
     * @return Returns the string <code>"Crypt"</code>.
     */
    @Override
    public String getAlgorithm() {
        return "Crypt";
    }

    /**
     * Accessor method to get the format of the encoded key.
     *
     * @return Returns the string <code>"RAW"</code>.
     */
    @Override
    public String getFormat() {
        return "RAW";
    }

    /**
     * Accessor method to get the encoded key.
     *
     * @return Returns the encoded byte array containing the key.
     */
    @Override
    public byte[] getEncoded() {
        return keyBytes;
    }
}
