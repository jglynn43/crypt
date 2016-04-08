package com.psi.crypt;

import java.security.Security;

/**
 *
 * @author John Glynn
 */
public class Tester {
    
    public static void main(String[] args) throws CryptException {
        Security.addProvider(new Provider());
        System.out.println(Crypt.crypt("@^vxDg*(", "hg"));
        // expect hgIfBSlO0pCJk
    }   
}
