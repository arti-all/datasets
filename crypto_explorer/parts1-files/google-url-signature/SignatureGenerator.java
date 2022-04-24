package com.qoomon.google.signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


/**
 * Google uri signer.
 *
 * @author b.brodersen
 */
public class SignatureGenerator {

    // This variable stores the binary key, which is computed from the string (Base64) key
    private byte[] key;

    public SignatureGenerator(String keyString) {
        // Convert the key from 'web safe' base 64 to binary
        keyString = keyString.replace('-', '+');
        keyString = keyString.replace('_', '/');
        this.key = DatatypeConverter.parseBase64Binary(keyString);
    }

    public String generate(String resource) {

        // Get an HMAC-SHA1 signing key from the raw key bytes
        SecretKeySpec sha1Key = new SecretKeySpec(key, "HmacSHA1");

        Mac mac;
        try {
            // Get an HMAC-SHA1 Mac instance and initialize it with the HMAC-SHA1 key
            mac = Mac.getInstance("HmacSHA1");
            mac.init(sha1Key);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // compute the binary signature for the request
        byte[] sigBytes = mac.doFinal(resource.getBytes());

        // base 64 encode the binary signature
        String signature = DatatypeConverter.printBase64Binary(sigBytes);

        // convert the signature to 'web safe' base 64
        signature = signature.replace('+', '-');
        signature = signature.replace('/', '_');
        return signature;
    }
}
