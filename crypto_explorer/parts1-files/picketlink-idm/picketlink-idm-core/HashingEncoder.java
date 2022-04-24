/*
 * JBoss, a division of Red Hat
 * Copyright 2012, Red Hat Middleware, LLC, and individual
 * contributors as indicated by the @authors tag. See the
 * copyright.txt in the distribution for a full listing of
 * individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.picketlink.idm.impl.credential;

import org.picketlink.idm.api.CredentialEncoder;
import org.picketlink.idm.api.User;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Implementation of {@link CredentialEncoder} based on password hashing (no salting functionality provided)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class HashingEncoder extends AbstractCredentialEncoder
{
   public static final String OPTION_CREDENTIAL_ENCODER_HASH_ALGORITHM = CredentialEncoder.CREDENTIAL_ENCODER_OPTION_PREFIX + "hashAlgorithm";

   // We use MD5 by default because of backwards compatibility
   private static final String OPTION_DEFAULT_HASH_ALGORITHM = "MD5";

   // Hashing algorithm. Possible examples are "SHA-256", "SHA1", "MD5"
   private String hashAlgorithm;

   @Override
   protected void afterInitialize()
   {
      hashAlgorithm = getEncoderProperty(OPTION_CREDENTIAL_ENCODER_HASH_ALGORITHM);
      if (hashAlgorithm == null)
      {
         hashAlgorithm = OPTION_DEFAULT_HASH_ALGORITHM;
      }

      log.info("Algorithm " + hashAlgorithm + " will be used for password hashing");
   }

   /**
    * Computes password hash based on configured hashAlgorithm and returns the result as a string in hexadecimal format
    *
    * @param username not used for this implementation
    * @param plainCredential password to input
    * @return hash of provided plainCredential
    */
   public String encodeCredential(String username, String plainCredential)
   {
      return toHexString(hashEncode(plainCredential));
   }

   /**
    * Computes hash of a string.
    *
    * @param text the hashed string
    * @return the string hash
    * @throws NullPointerException if text is null
    */
   private byte[] hashEncode(String text)
   {
      // arguments check
      if (text == null)
      {
         throw new NullPointerException("null text");
      }

      try
      {
         MessageDigest md = getMessageDigest();
         md.update(text.getBytes());
         return md.digest();
      }
      catch (NoSuchAlgorithmException e)
      {

         throw new RuntimeException("Cannot find hash algorithm: " + hashAlgorithm, e);
      }
   }

   protected MessageDigest getMessageDigest() throws NoSuchAlgorithmException
   {
      return MessageDigest.getInstance(hashAlgorithm);
   }

   /**
    * Returns a string in the hexadecimal format.
    *
    * @param bytes the converted bytes
    * @return the hexadecimal string representing the bytes data
    * @throws IllegalArgumentException if the byte array is null
    */
   protected String toHexString(byte[] bytes)
   {
      if (bytes == null)
      {
         throw new IllegalArgumentException("byte array must not be null");
      }
      StringBuffer hex = new StringBuffer(bytes.length * 2);
      for (int i = 0; i < bytes.length; i++)
      {
         hex.append(Character.forDigit((bytes[i] & 0XF0) >> 4, 16));
         hex.append(Character.forDigit((bytes[i] & 0X0F), 16));
      }
      return hex.toString();
   }
}
