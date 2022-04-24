package sec.blockfs.blockutility;

import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

public class BlockUtility {
    // cross-module variables
    public static final int KEY_SIZE = 2048;
    public static final String DIGEST_ALGORITHM = "SHA-512";
    public static final int BLOCK_SIZE = 4096;
    public static final int SIGNATURE_SIZE = 256;
    public static final int DIGEST_SIZE = 64;

    // utility methods
    public static String getKeyString(byte[] contents) {
        String keyString = "";
        int stringSize = 10;
        for (int i = 0; i < contents.length && i < stringSize; ++i) {
            keyString += contents[i];
        }
        return keyString;
    }

    public static byte[] digest(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digestAlgorithm = MessageDigest.getInstance(DIGEST_ALGORITHM);
        return digestAlgorithm.digest(data);
    }

    public static boolean verifyDataIntegrity(byte[] data, byte[] signature, byte[] publicKeyBytes) {
        try {
            PublicKey publicKey = regeneratePublicKey(publicKeyBytes);
            return verifyDataIntegrity(data, signature, publicKey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean verifyDataIntegrity(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            Signature rsaSignature = Signature.getInstance("SHA512withRSA", "SunRsaSign");

            rsaSignature.initVerify(publicKey);
            rsaSignature.update(data, 0, data.length);

            // verify data integrity
            return rsaSignature.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static PublicKey regeneratePublicKey(byte[] publicKeyBytes)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        return keyFactory.generatePublic(pubKeySpec);
    }

    public static String generateString(int length) {
        String chars = new String("1234567890abcdefghijklmnopqrstuvxyz");// .-,/*-+@#£$%&()=?");
        Random rand = new Random();

        char[] text = new char[length];
        for (int i = 0; i < length; i++) {
            text[i] = chars.charAt(rand.nextInt(chars.length()));
        }
        return new String(text);
    }
}
