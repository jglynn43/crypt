package com.psi.crypt;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

/**
 * Implementation of AlgorithmParameters SPI for crypt(3C) algorithm.
 *
 * @author John Glynn
 * @version 1.2
 */
public class CryptAlgorithmParameters extends AlgorithmParametersSpi {

    /**
     * Internal, opaque container for parameter specification. In this case, it
     * is the same as the CryptAlgorithmParameterSpec member
     */
    protected byte[] parameters;

    /**
     * No argument constructor required for factory methods.
     */
    public CryptAlgorithmParameters() {
    }

    /**
     * Factory accessor method to get opaque representation of parameters.
     *
     * @return Byte array containing encoded representation of parameters.
     * @throws java.io.IOException
     */
    @Override
    protected byte[] engineGetEncoded() throws IOException {
        return engineGetEncoded("RAW");
    }

    /**
     * Factory accessor method to get opaque representation of parameters in the
     * format requested.
     *
     * @param format String describing the encoding scheme of the encoded
     * parameters. Note that only <code>"RAW"</code> is supported.
     * @return Byte array containing encoded representation of parameters.
     * @exception java.io.IOException Exception is thrown for any request other
     * than <code>"RAW"</code>.
     */
    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if (format.compareTo("RAW") == 0) {
            return parameters;
        }

        throw new IOException("Only RAW format is supported");
    }

    /**
     * Factory accessor method to get the underlying specification.
     *
     * @param paramspec Class object used to instantiate new specification.
     * @return Base class initialized to new CryptAlgorithmParameterSpec.
     * @exception InvalidParameterSpecException Thrown when requesting any class
     * other than CryptAlgorithmParameterSpec.
     */
    @Override
    protected AlgorithmParameterSpec engineGetParameterSpec(Class paramspec)
            throws InvalidParameterSpecException {
        if (paramspec.getName().endsWith("CryptAlgorithmParameterSpec")) {
            return new CryptAlgorithmParameterSpec(parameters);
        }

        throw new InvalidParameterSpecException(
                "Only CryptAlgorithmParameterSpec supported");
    }

    /**
     * Initialize the internal representation with a specification.
     *
     * @param paramSpec The specification used for this parameter.
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) {
        parameters = ((CryptAlgorithmParameterSpec) paramSpec).getSalt();
    }

    /**
     * Initialize the internal representation with a raw byte array.
     *
     * @param params The byte array used to initialize the parameter. These must
     * be in <code>"RAW"</code> format.
     * @throws java.io.IOException
     */
    @Override
    protected void engineInit(byte[] params) throws IOException {
        engineInit(params, "RAW");
    }

    /**
     * Initialize the internal representation with a raw byte array in the
     * format given.
     *
     * @param params The byte array used to initialize the parameter.
     * @param format The string containing the name of the format used.
     * @exception java.io.IOException Thrown when any format other than
     * <code>"RAW"</code> is used.
     */
    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        if (format.compareTo("RAW") == 0) {
            engineInit(new CryptAlgorithmParameterSpec(params));
        }

        throw new IOException("Only RAW format is supported");
    }

    /**
     * Return a descriptive string describing the purpose of the class.
     *
     * @return Returns <code>"Parameter: salt in RAW byte format
     * (char)"</code>
     */
    @Override
    protected String engineToString() {
        return "Parameter: salt in RAW byte format (char)";
    }
}
