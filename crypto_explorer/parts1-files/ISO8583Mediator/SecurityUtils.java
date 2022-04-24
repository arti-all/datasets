package com.finance.iso.iso8583.jpos.util;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.CryptoException;

public class SecurityUtils {

	public static byte calculateLRC(byte[] data) {
	    byte checksum = 0;
	    for (int i = 0; i < data.length; i++) {
	        checksum = (byte) ((checksum + data[i]) & 0xFF);
	    }
	    checksum = (byte) (((checksum ^ 0xFF) + 1) & 0xFF);
	    return checksum;
	}
	
	public static byte[] encryptSymmetric(byte[] key, byte[] dataToEncrypt)
			throws CryptoException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance("AES");
		MessageDigest md = MessageDigest.getInstance("MD5"); //based on the strength of the key, change this algorithm. 
															 //128 bits - MD5			256 bits - SHA-256
															 //512 bits - SHA-512. Also, please include JCE to use 256 or 512 bits keys. 
		
		byte[] digetstKey = md.digest(key);
		SecretKeySpec k = new SecretKeySpec(digetstKey, "AES");
		c.init(Cipher.ENCRYPT_MODE, k);
		byte[] encryptedData = c.doFinal(dataToEncrypt);
		return encryptedData;
	}

	public static byte[] decryptSymmetric(byte[] key, byte[] dataToDecrypt)
			throws CryptoException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher c = Cipher.getInstance("AES");
		MessageDigest md = MessageDigest.getInstance("MD5"); //based on the strength of the key, change this algorithm. 
															 //128 bits - MD5			256 bits - SHA-256
															 //512 bits - SHA-512. Also, please include JCE to use 256 or 512 bits keys. 
		byte[] digetstKey = md.digest(key);
		SecretKeySpec k = new SecretKeySpec(digetstKey, "AES");
		c.init(Cipher.DECRYPT_MODE, k);
		byte[] decryptedData = c.doFinal(dataToDecrypt);
		return decryptedData;
	}

}
