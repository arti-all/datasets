package com.booxle.security;

import com.booxle.BooxleException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.enterprise.inject.Produces;
import java.io.FileOutputStream;

import static javax.crypto.KeyGenerator.getInstance;

/**
 * @author Antoine Sabot-Durand
 */
public class MyProducers {


    final static String LOG_FILE = "./logsecret.txt";

    private final static String CIPHER_TYPE = "Blowfish";


    @Produces
    protected CipherOutputStream cipherOutStreamProducer() {
        try {
            SecretKey key = getInstance(CIPHER_TYPE).generateKey();
            Cipher cipher = Cipher.getInstance(CIPHER_TYPE);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return new CipherOutputStream(new FileOutputStream(LOG_FILE), cipher);
        } catch (Exception e) {
            throw new BooxleException(e);
        }
    }

}
