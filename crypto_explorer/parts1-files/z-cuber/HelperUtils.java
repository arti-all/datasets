package org.zoltor.common;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.zoltor.common.Config.logger;

/**
 * Created by zoltor on 26.10.14.
 */
public class HelperUtils {

    /**
     * Concatenate strings to one and get mad5 hash for it
     * @param encoding Encoding for result string
     * @param strings Strings which should be concatenated to one
     * @return String with md5 hash of result concatenated string
     */
    public static String getMd5Digest(Config.ENCODING encoding, String... strings) {
        StringBuilder sb = new StringBuilder();
        String result = "";
        for (String string : strings) {
            sb.append(string);
        }
        if (sb.length() > 0) {
            try {
                MessageDigest digest = MessageDigest.getInstance("MD5");
                byte[] md5Digest = digest.digest(sb.toString().getBytes());
                result = new String(md5Digest, encoding.getEncodingName());
            } catch (NoSuchAlgorithmException e) {
                logger.error("Decode algorithm not found");
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                logger.error("Wrong encoding");
                e.printStackTrace();
            }
        }
        return result;
    }

    /**
     * Concatenate strings to one and get mad5 hash for it, with default encoding from config
     * @param strings Strings which should be concatenated to one
     * @return String with md5 hash of result concatenated string
     */
    public static String getMd5Digest(String... strings) {
        return getMd5Digest(Config.dataEncoding, strings);
    }

    public static Date getDateFromDb(String sqlDateField) {
        try {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(sqlDateField);
        } catch (ParseException e) {
            e.printStackTrace();
            return new Date();
        }
    }
}
