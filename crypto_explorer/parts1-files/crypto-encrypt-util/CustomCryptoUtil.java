package org.wso2.carbon.custom.util;

import org.apache.axiom.om.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import javax.crypto.Cipher;

public class CustomCryptoUtil {
    public static void main(String[] args) throws Exception {
        System.out.println(encrypt(args[0], args[1], args[2], args[3]));
    }

    public static String encrypt(String plainTextPassword, String keyStoreFile, String keyStorePassword,
            String certificateAlias) throws Exception {
        byte[] encryptedKey;

        KeyStore keyStore = KeyStore.getInstance("JKS");
        InputStream resourceAsStream = new FileInputStream(keyStoreFile);
        keyStore.load(resourceAsStream, keyStorePassword.toCharArray());
        Certificate[] certs = keyStore.getCertificateChain(certificateAlias);
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher = Cipher.getInstance("RSA", "BC");
        cipher.init(1, certs[0].getPublicKey());
        encryptedKey = cipher.doFinal(plainTextPassword.getBytes());

        return Base64.encode(encryptedKey);

    }

}
