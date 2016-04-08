package com.psi.crypt;

import java.security.spec.KeySpec;
import javax.crypto.SecretKey;

/**
 * Container for raw bytes of clear-text password
 *
 * @author John Glynn
 * @version 1.2
 */
public class CryptKeySpec implements KeySpec, SecretKey {

    /**
     * Internal storage for the key bytes
     *
     * @serial The clear-text password in a byte[].
     */
    private final byte[] bytes;

    /**
     * Create a specification from a raw byte array.
     *
     * @param raw The raw byte array.
     */
    public CryptKeySpec(byte[] raw) {
        bytes = new byte[8];

        for (int i = 0; i < bytes.length; ++i) {
            if (i < raw.length) {
                bytes[i] = (byte) (raw[i] & 0x7f);
            } else {
                bytes[i] = (byte) 0;
            }
        }
    }

    /**
     * Create a specification from a char array.
     *
     * @param chars The char array containing the clear-text password.
     */
    public CryptKeySpec(char[] chars) {
        bytes = new byte[8];

        for (int i = 0; i < bytes.length; ++i) {
            if (i < chars.length) {
                bytes[i] = (byte) ((int) chars[i] & 0x7f);
            } else {
                bytes[i] = (byte) 0;
            }
        }
    }

    /**
     * Create a specification from an existing key.
     *
     * @param key The key containing the encoded bytes.
     */
    public CryptKeySpec(CryptKey key) {
        bytes = key.getEncoded();
    }

    /**
     * Accessor method which returns the name of the algorithm used.
     *
     * @return Returns the string <code>"Crypt"</code>.
     */
    @Override
    public String getAlgorithm() {
        return "Crypt";
    }

    /**
     * Accessor method which returns the name of the algorithm encoding format
     * used.
     *
     * @return Returns the string <code>"RAW"</code>.
     */
    @Override
    public String getFormat() {
        return "RAW";
    }

    /**
     * Accessor method which returns the internal byte array of the key
     * specification.
     *
     * @return Returns the byte[] of the key specification.
     */
    @Override
    public byte[] getEncoded() {
        return bytes;
    }

    /**
     * Comparison method which compares the individual bytes of the key
     * specification.
     *
     * @param obj Another CryptKeySpec.
     * @return Returns <b>true</b> or <b>false</b>
     */
    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof CryptKeySpec)) {
            return false;
        }
        byte[] other = ((CryptKeySpec) obj).getEncoded();

        if (other.length != bytes.length) {
            return false;
        }

        for (int i = 0; i < bytes.length; ++i) {
            if (bytes[i] != other[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Comparison method used for ordering CryptKeySpec objects within
     * containers.
     *
     * @return Integer value of the hash
     */
    @Override
    public int hashCode() {
        int hash = 0;

        for (int i = 0; i < bytes.length - 1; i += 2) {
            hash += (bytes[i] ^ bytes[i + 1]) << (24 - (i * 4));
        }

        return hash;
    }
}
