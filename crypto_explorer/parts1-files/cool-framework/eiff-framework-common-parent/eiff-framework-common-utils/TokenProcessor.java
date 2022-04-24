package com.eiff.framework.common.utils.token;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 
 */
public class TokenProcessor {

    private static TokenProcessor instance = new TokenProcessor();

    protected TokenProcessor() {

    }

    public static TokenProcessor getInstance() {
        return instance;
    }

    /**
     * 生成token
     * 
     * @param msg 
     * @param timeChange true，是追加时间戳，false 不追加时间戳
     * @return
     */
    public synchronized String generateToken(String msg, boolean timeChange) {
        try {
            long current = System.nanoTime();
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(msg.getBytes());
            if (timeChange) {
                byte now[] = (new Long(current)).toString().getBytes();
                md.update(now);
            }
            return toHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private String toHex(byte buffer[]) {
        StringBuffer sb = new StringBuffer(buffer.length * 2);
        for (int i = 0; i < buffer.length; i++) {
            sb.append(Character.forDigit((buffer[i] & 240) >> 4, 16));
            sb.append(Character.forDigit(buffer[i] & 15, 16));
        }
        return sb.toString();
    }
}
