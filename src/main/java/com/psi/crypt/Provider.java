package com.psi.crypt;

/**
 * Implementation of Provider class to extend the java security Provider
 *
 * @author John Glynn
 * @version 1.2
 */
public final class Provider extends java.security.Provider {

    /**
     * No argument constructor required for implementation. This initializes the
     * base class and adds the crypt digest and algorithm parameters to the list
     * of available modules in the security model.
     */
    public Provider() {
        super("PSI", 1.2, "DES Crypt");

        put("AlgorithmParameters.Crypt",
                "com.psi.crypt.CryptAlgorithmParameters");
        put("MessageDigest.Crypt", "com.psi.crypt.CryptDigest");
    }
}
