package com.apruve;

import java.math.BigInteger;
import java.security.MessageDigest;

public class ShaUtil {

	public static String getDigest(String data) {
		try {
			MessageDigest mac = MessageDigest.getInstance("SHA-256");
			mac.update(data.getBytes("UTF-8"));
			return new String(toHex(mac.digest())).toLowerCase();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static String toHex(byte[] bytes) {
		BigInteger bi = new BigInteger(1, bytes);
		return String.format("%0" + (bytes.length << 1) + "X", bi);
	}
}
