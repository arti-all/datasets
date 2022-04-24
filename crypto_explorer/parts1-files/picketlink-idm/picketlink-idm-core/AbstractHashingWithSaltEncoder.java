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

import java.security.MessageDigest;

/**
 * Abstract implementation of {@link org.picketlink.idm.api.CredentialEncoder} based on hashing+salting of passwords.
 * Subclasses need to override method {@link #getSalt} for compute salt
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractHashingWithSaltEncoder extends HashingEncoder
{

   /**
    * Computes password hash based on configured hashAlgorithm and on salt provided by method {@link #getSalt}.
    * It returns the result as a string in hexadecimal format
    *
    * @param username can be used for computing salt
    * @param rawPassword password to encode
    * @return hashed and salted rawpassword in hexadecimal format
    */
   @Override
   public String encodeCredential(String username, String rawPassword)
   {
      try
      {
         MessageDigest messageDigest = getMessageDigest();
         String salt = getSalt(username);
         messageDigest.update(saltPassword(rawPassword, salt).getBytes("UTF-8"));
         byte[] encodedPassword = messageDigest.digest();
         return toHexString(encodedPassword);
      }
      catch (Exception e)
      {
         throw new RuntimeException("Error encoding password", e);
      }
   }

   private String saltPassword(String rawPassword, String salt)
   {
      return rawPassword + salt;
   }

   /**
    * Computing salt for concrete user
    *
    * @param username
    * @return salt
    */
   protected abstract String getSalt(String username);
}
