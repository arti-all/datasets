package edu.neumont.diyauto.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.ejb.Local;
import javax.ejb.Stateless;

/**
 * Encodes the given password using SHA-256.
 * 
 * @author jcummings
 *
 */
@Stateless
@Local(PasswordEncoder.class)
public class Sha256PasswordEncoder implements PasswordEncoder {
	public String encode(String password) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] hashed = md.digest(password.getBytes());
			StringBuilder sb = new StringBuilder();
	        for(int i=0; i< hashed.length ;i++)
	        {
	            sb.append(Integer.toString((hashed[i] & 0xff) + 0x100, 16).substring(1));
	        }
	        return sb.toString();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Can't find SHA-256 digest!");
		}
		
	}
}
