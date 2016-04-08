package com.psi.crypt;

import java.security.MessageDigest;
import java.security.AlgorithmParameters;

/**
 * A hashing digest which uses the crypt(3C) algorithm.
 *
 * @author John Glynn
 */
public final class CryptDigest extends MessageDigest {

    /**
     * The parameters needed for this algorithm, i.e., the salt.
     */
    private AlgorithmParameters parameters;

    /**
     * Internal storage for the data to be digested, i.e., the password.
     */
    private final byte[] buffer;

    /**
     * The current offset into the buffer where the next byte is to be copied.
     */
    private int offset;

    /**
     * No argument constructor required for Factory pattern.
     */
    public CryptDigest() {
        super("Crypt");

        buffer = new byte[8];
        engineReset();
    }

    /**
     * Initialize the AlgorithmParameters field.
     *
     * @param params An opaque representation of the parameters.
     */
    public void init(AlgorithmParameters params) {
        parameters = params;
    }

    /**
     * Performs the hash on the data currently held in the internal buffer.
     *
     * @return The byte array containing the base64 string in crypt format.
     */
    @Override
    protected byte[] engineDigest() {
        CryptKeySpec spec = new CryptKeySpec(buffer);
        CryptImplementation crypt = new CryptImplementation();
        crypt.setupSalt(parameters);
        crypt.makeKeyTable(new CryptKey(spec));
        crypt.encrypt();

        return crypt.getCrypt3Buffer().getBytes();
    }

    /**
     * Resets the internal counters and buffers to all zeroes.
     */
    @Override
    protected void engineReset() {
        offset = 0;
        parameters = null;

        for (int i = 0; i < buffer.length; ++i) {
            buffer[i] = (byte) 0;
        }
    }

    /**
     * Adds another byte to the internal array if that array is not already
     * full. At most eight bytes are stored in the internal array.
     *
     * @param input The byte to be added to the array.
     */
    @Override
    protected void engineUpdate(byte input) {
        if (offset < buffer.length) {
            buffer[offset] = input;
            ++offset;
        }
    }

    /**
     * Adds a given number of bytes from an array at the given offset to the
     * internal array if that array is not already full. At most eight bytes are
     * stored in the internal array.
     *
     * @param input The byte array from which bytes are copied.
     * @param inputOffset The starting location to get bytes from in the input
     * array.
     * @param len The number of bytes to be copied.
     */
    @Override
    protected void engineUpdate(byte[] input, int inputOffset, int len) {
        for (int i = 0;
                offset < buffer.length && inputOffset < input.length && i < len;
                ++offset, ++inputOffset, ++i) {
            buffer[offset] = input[inputOffset];
        }
    }

    /**
     * Factory accessor method to get the length of the byte[] that will be
     * output by the digest.
     *
     * @return The length of the array output by the digest.
     */
    @Override
    protected int engineGetDigestLength() {
        return 13;
    }
}
