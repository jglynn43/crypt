package com.psi.crypt;

import java.security.Security;
import java.sql.Timestamp;
import java.util.Date;

/**
 *
 * @author John Glynn
 */
public class Tester {
    
    public static void main(String[] args) throws CryptException {
        Security.addProvider(new Provider());
        
        final String password = "@^vxDg*(";
        final String salt = "hg";
        
        System.out.println(Crypt.crypt(password, salt));
        // expect hgIfBSlO0pCJk
        
        // try 10000 crypts
        System.out.println(new Timestamp(new Date().getTime()));
        for (int i = 0 ; i < 10000; ++i) {
            Crypt.crypt(password, salt);
        }
        System.out.println(new Timestamp(new Date().getTime()));
    }   
}
