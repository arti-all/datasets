package de.proskor.gravatar;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class GravatarUtils {
	private static GravatarUtils instance;
	private MessageDigest md;

	private GravatarUtils() {
		try {
			md = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			// should not happen
		}
	}

	public static GravatarUtils getInstance() {
		if (instance == null) {
			instance = new GravatarUtils();
		}
		return instance;
	}

	public String getHash(String email) {
		md.update(email.trim().toLowerCase().getBytes());
		BigInteger hash = new BigInteger(1, md.digest());
		return hash.toString(16);
	}
}
