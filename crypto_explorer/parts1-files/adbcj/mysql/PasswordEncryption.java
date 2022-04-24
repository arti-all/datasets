/*
	This file is part of ADBCJ.

	ADBCJ is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	ADBCJ is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with ADBCJ.  If not, see <http://www.gnu.org/licenses/>.

	Copyright 2008  Mike Heath
*/
package org.adbcj.mysql.codec;

import org.adbcj.DbException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class PasswordEncryption {

    public static byte[] encryptPassword(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");

            byte[] hash1 = md.digest(password.getBytes("UTF-8"));

            md.reset();
            byte[] hash2 = md.digest(hash1);

            md.reset();
            md.update(salt);
            md.update(hash2);

            byte[] digest = md.digest();
            for (int i = 0; i < digest.length; i++) {
                digest[i] = (byte) (digest[i] ^ hash1[i]);
            }
            return digest;
        } catch (Exception e) {
            throw DbException.wrap(e);
        }
    }

}
