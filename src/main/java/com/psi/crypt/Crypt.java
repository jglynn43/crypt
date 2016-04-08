package com.psi.crypt;

import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author john
 */
public class Crypt {
    private static final Logger LOG = Logger.getLogger(Crypt.class.getName());
    
    public static String crypt(byte[] data) throws CryptException {
        try {
            return doCrypt(data, generateSalt());
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            LOG.log(Level.SEVERE, null, ex);
            throw new CryptException(ex);
        }
    }
    
    public static String crypt(byte[] data, byte[] salt) throws CryptException {
        try {
            return doCrypt(data, salt);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            LOG.log(Level.SEVERE, null, ex);
            throw new CryptException(ex);
        }
    }
    
    public static String crypt(String data) throws CryptException {
        try {
            return doCrypt(data.getBytes(), generateSalt());
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            LOG.log(Level.SEVERE, null, ex);
            throw new CryptException(ex);
        }
    }
    
    public static String crypt(String data, String salt) throws CryptException {
        try {
            return doCrypt(data.getBytes(), charToBytes(salt.toCharArray()));
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            LOG.log(Level.SEVERE, null, ex);
            throw new CryptException(ex);
        }
    }
    
    private static byte[] generateSalt() {
        return charToBytes(UUID.randomUUID().toString().replaceAll("-", "")
                .substring(0,2).toCharArray());
    }
    
    private static byte[] charToBytes(char[] chars) {
        byte[] bytes = new byte[chars.length];
        for (int i = 0; i < chars.length; ++i) {
            bytes[i] = (byte)CryptUtility.asciiToBinary(chars[i]);
        }
        return bytes;
    }
    
    private static String doCrypt(byte[] data, byte[] salt) 
            throws NoSuchAlgorithmException, InvalidParameterSpecException {
        CryptDigest crypt = (CryptDigest) MessageDigest.getInstance("Crypt");
        CryptAlgorithmParameterSpec spec = new CryptAlgorithmParameterSpec(salt);
        AlgorithmParameters params  = AlgorithmParameters.getInstance("Crypt");
        params.init((AlgorithmParameterSpec) spec);
        crypt.init(params);

        for (int i = 0; i < data.length; ++i) {
            crypt.update(data[i]);
        }

        return new String(crypt.digest());
    }
}
