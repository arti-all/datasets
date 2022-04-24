package com.cascaio.security;

import java.security.SecureRandom;

/**
 * User: jpkrohling
 * Date: 2013-05-11 8:10 PM
 */
public class KeyGenerator {

	/**
	 * This method generates a secure random key of 64 bytes.
	 *
	 * @return
	 */
	public static String generate() {
		SecureRandom random = new SecureRandom();
		byte privateKeyBytes[] = new byte[64];
		random.nextBytes(privateKeyBytes);

		StringBuilder sb = new StringBuilder();
		for (byte b : privateKeyBytes) {
			sb.append(String.format("%02X", b));
		}
		return sb.toString();
	}
}
