package de.paluch.configserver.service;

import de.paluch.configserver.model.config.ConfigEncryption;
import org.apache.commons.codec.binary.Base64;
import org.springframework.util.StreamUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:mpaluch@paluch.biz">Mark Paluch</a>
 * @since 04.04.13 08:46
 */
public class Encryption {

    public static String TOKEN_START = "{";
    public static String TOKEN_END = "}";
    public static String DELIMITTER = ":";

    public static String REGEX = "\\" + TOKEN_START + "(.*)\\" + DELIMITTER + "(.*)\\" + TOKEN_END;
    public static Pattern pattern = Pattern.compile(REGEX);

    /**
     *
     * @param value
     * @return true if String is in form of {cipherId:cipherTextInBase64}
     */
    public static boolean isEncrypted(String value) {
        if (value != null) {
            return pattern.matcher(value).matches();
        }

        return false;
    }

    /**
     *
     * @param value String in form of {cipherId:cipherTextInBase64}
     * @param encryptions
     * @return Plaintext
     */
    public static String decrypt(String value, List<ConfigEncryption> encryptions) {
        Matcher matcher = pattern.matcher(value);

        assert matcher.matches();
        String cipherId = matcher.group(1);
        String cipherText = matcher.group(2);


        ConfigEncryption encryption = getEncryption(cipherId, encryptions);

        if (encryption == null) {
            throw new IllegalArgumentException("Cannot resolve cipher with reference id " + cipherId + " from " +
                                                       value);
        }

        try {
            byte[] bytes = decrypt(Base64.decodeBase64(cipherText.getBytes()), encryption);
            String plainText = new String(bytes);
            return plainText;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot decrypt " + value, e);
        }
    }

    /**
     *
     * @param cipherId
     * @param plainText
     * @param encryptions
     * @return String in form of {cipherId:cipherTextInBase64}
     */
    public static String encrypt(String cipherId, String plainText, List<ConfigEncryption> encryptions) {
        ConfigEncryption encryption = getEncryption(cipherId, encryptions);

        if (encryption == null) {
            throw new IllegalArgumentException("Cannot resolve cipher with reference id " + cipherId + " from " +
                                                       cipherId);
        }

        try {
            byte[] bytes = encrypt(plainText.getBytes(), encryption);
            return TOKEN_START + cipherId + DELIMITTER + new String(Base64.encodeBase64(bytes)) +
                    TOKEN_END;
        } catch (Exception e) {
            throw new IllegalStateException("Cannot encrypt " + cipherId + "/" + plainText, e);
        }
    }

    private static byte[] decrypt(byte[] input, ConfigEncryption encryption)
            throws GeneralSecurityException, IOException {

        Cipher cipher = initializeCipher(encryption, Cipher.DECRYPT_MODE);
        return runCrypto(input, cipher);
    }


    private static byte[] encrypt(byte[] input, ConfigEncryption encryption)
            throws GeneralSecurityException, IOException {
        Cipher cipher = initializeCipher(encryption, Cipher.ENCRYPT_MODE);
        return runCrypto(input, cipher);
    }

    private static byte[] runCrypto(byte[] input, Cipher cipher) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        CipherOutputStream cos = new CipherOutputStream(output, cipher);
        cos.write(input);
        cos.close();

        return output.toByteArray();
    }

    private static ConfigEncryption getEncryption(String cipherId, List<ConfigEncryption> encryptions) {

        for (ConfigEncryption encryption : encryptions) {
            if (encryption.getId().equals(cipherId)) {
                return encryption;
            }
        }
        return null;
    }

    private static Cipher initializeCipher(ConfigEncryption encryption, int mode)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(encryption.getCipher());
        String algorithmId = cipher.getAlgorithm().split("/")[0];

        SecretKeySpec keySpec = new SecretKeySpec(Base64.decodeBase64(encryption.getKey().getBytes()), algorithmId);


        IvParameterSpec ivSpec = null;
        if (encryption.getIvSpec() != null) {
            ivSpec = new IvParameterSpec(Base64.decodeBase64(encryption.getIvSpec().getBytes()));
            cipher.init(mode, keySpec, ivSpec);
        } else {
            cipher.init(mode, keySpec);
        }
        return cipher;
    }


}
