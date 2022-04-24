package com.app.util;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.UUID;

import org.springframework.stereotype.Service;

import sun.misc.BASE64Encoder;

@Service
public class Utility {

	
	/* GENERATE OTP
	 * */
	public Integer RandomNumberGenerate()
	{
		Random random = new Random(); 
    	int randNum= random.nextInt(999999);
    	
    	return randNum;
	}
	
	
	public String RandomUUIDGenerate()
    {
    	String uniqueID = UUID.randomUUID().toString();
    	
    	return uniqueID;
    }

	
	/* ENCRYPY PASSWORD WITH MD5 
	 * */
    public String encrypt(String plaintext, String algorithm, String encoding) throws Exception
    {
        MessageDigest msgDigest = null;
        String hashValue = null;
        try
        {
            msgDigest = MessageDigest.getInstance(algorithm);
            msgDigest.update(plaintext.getBytes(encoding));
            byte rawByte[] = msgDigest.digest();
            hashValue = (new BASE64Encoder()).encode(rawByte);
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("No Such Algorithm Exists");
        }
        catch (UnsupportedEncodingException e)
        {
            System.out.println("The Encoding Is Not Supported");
        }
        
        return hashValue;
    }
}
