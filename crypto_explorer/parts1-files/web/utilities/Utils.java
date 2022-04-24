package org.seventyeight.utils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Utils {

	public static String md5( String phrase ) throws NoSuchAlgorithmException {
		MessageDigest m = MessageDigest.getInstance( "MD5" );
		byte[] data = phrase.getBytes();
		m.update( data, 0, data.length );
		BigInteger i = new BigInteger( 1, m.digest() );
		return String.format( "%1$032X", i );
	}
}
