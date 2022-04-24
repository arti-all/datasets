package com.lissenberg.blog.services;

import javax.ejb.Stateless;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/**
 * Security services
 *
 * @author Harro Lissenberg
 */
@Stateless
public class SecurityService {

    private static final int ITERATIONS = 10000;

    Logger LOG = Logger.getLogger(SecurityService.class.getName());

    /**
     * Generates a hash for the given input
     *
     * @param input
     * @return a hex string containing the hash
     */
    public String createHash(final String input) {
        String hash = null;
        try {
            hash = calculateHash(input);
            for (int i = 0; i < ITERATIONS; i++) {
                // iterate thousands of times to make it slower to brute force
                hash = calculateHash(hash);
            }
        } catch (NoSuchAlgorithmException e) {
            LOG.severe(e.getMessage());
        } catch (UnsupportedEncodingException e) {
            LOG.severe(e.getMessage());
        }
        return hash;
    }

    private String calculateHash(String input) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA");
        md.update(input.getBytes("UTF-8"));
        byte[] digest = md.digest();
        String hash = new BigInteger(1, digest).toString(16);
        // return a 40 character hex string, pad with zeroes if shorter
        return String.format("%40s", hash).replace(' ', '0');
    }
}
