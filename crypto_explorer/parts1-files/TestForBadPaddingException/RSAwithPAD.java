package org.wso2;

import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class RSAwithPAD {
    public static void main(String [] args) throws Exception {
        String plaintext = "aaaaaa";
        byte[] ciphertext =encrypt((plaintext));
        String recoveredPlaintext = decrypt(ciphertext);
        System.out.println("recoveredPlaintext   "+recoveredPlaintext);
    }

    private static byte [] encrypt(String plaintext) throws Exception {
        KeyStore keyStore = getKeyStore();
        Certificate[] certs = keyStore.getCertificateChain("wso2carbon");
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, certs[0].getPublicKey());
        return cipher.doFinal(plaintext.getBytes());
    }

    private static String decrypt(byte [] ciphertext) throws Exception {

        KeyStore keyStore = getKeyStore();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("wso2carbon",
                "wso2carbon".toCharArray());
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherbyte=cipher.doFinal(ciphertext);
        return new String(cipherbyte);
    }

    public static KeyStore getKeyStore() throws Exception {

        String file ="wso2carbon.jks";
        KeyStore keyStore = KeyStore
                .getInstance("JKS");

        String password = "wso2carbon";
        FileInputStream in = null;
        try {
            in = new FileInputStream(file);
            keyStore.load(in, password.toCharArray());
        } finally {
            if (in != null) {
                in.close();
            }
        }
        return keyStore;
    }
}