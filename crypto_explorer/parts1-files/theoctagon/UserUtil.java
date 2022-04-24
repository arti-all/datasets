package com.meltmedia.util;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.apache.shiro.crypto.hash.Sha512Hash;

import com.meltmedia.data.User;


public class UserUtil {
  private static SecureRandom random = new SecureRandom();
  
  private static String createHashPassword(Object password, Object salt) {
    return new Sha512Hash(password, salt, 1024).toBase64();
  }  
  
  /**
   * Create a salt and set the password for the given user.
   */
  public static <E extends User> E setupNewPassword(E user, char[] newPassword) {
    // Build a salt for the actor
    user.setSalt(new BigInteger(64, random).toString(32));
    
    // Create the password as a hash of the password and the salt
    user.setPassword(createHashPassword(newPassword, user.getSalt()));

    return user;
  }
}
