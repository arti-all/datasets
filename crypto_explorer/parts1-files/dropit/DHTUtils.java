package com.anghiari.dropit.requestserver.service;

import com.anghiari.dropit.commons.KeyId;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author rajith
 * @author gayashan
 * @version ${Revision}
 */
public class DHTUtils {
    private static final int KEYSPACE = 8;    //keyspace = 32 , should be enough

    /**
     * Generate a hash ID for the given String key
     *
     * @param key File name as the key to hash
     * @return KeyId object with hash inside
     */
    public static KeyId generateKeyId(String key) {
        try {
            KeyId keyId = new KeyId(0);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            byte[] hash = messageDigest.digest(key.getBytes());
            int keySpaceBytes = KEYSPACE / 4;
            for (int i = 0; i < Math.min(hash.length, keySpaceBytes); ++i) {
                keyId.setHashId(keyId.getHashId() | (((long) hash[i] & 0xff) << (i * 4)));
            }
            return keyId;
        } catch (NoSuchAlgorithmException e) {
            //TODO: handle this exception
            e.printStackTrace();
        }
        return null;
    }

}
