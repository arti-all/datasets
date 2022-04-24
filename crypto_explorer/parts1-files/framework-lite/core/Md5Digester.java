package it.cilea.core.util;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.lang.StringUtils;

public final class Md5Digester {

	public static String getDigestString(String plainText) {		
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("MD5"); // step 2
		} catch (NoSuchAlgorithmException e) {

		}
		try {
			md.update(plainText.getBytes("UTF-8")); // step 3
		} catch (UnsupportedEncodingException e) {

		}
		StringBuffer digestedString = new StringBuffer();
		
		byte raw[] = md.digest(); // step 4
		for(int i = 0; i < raw.length; i++)        
			digestedString.append("+" + raw[i]);
        
		return StringUtils.replace(digestedString.toString(),"+-","-");
	}
	
	public static void main(String[] args) {
	}

}
