package com.whyun.util.security;

import java.security.SecureRandom;


public class RandomString {
	public static String rand() {
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[16];
	    random.nextBytes(bytes);
	    
	    return new String(org.apache.commons.codec.binary.Hex.encodeHex(bytes));
	}
	
	public static void main(String[] argc) {
		System.out.println(rand());
	}
}
