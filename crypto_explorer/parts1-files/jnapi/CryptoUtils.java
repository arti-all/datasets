package jnapi.utils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Cryptographic related util methods
 *
 * @author Maciej Dragan
 */
public class CryptoUtils {

    /**
     * Calculate md5sum hex from date
     *
     * @param data Data to use for calculation
     * @return MD5 sum hex
     */
    public static String md5sum(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(data);
            byte[] result = digest.digest();
            return String.format("%032x", new BigInteger(1, result));
        } catch (NoSuchAlgorithmException e) {
            // Fail silently
        }
        return null;
    }

}
