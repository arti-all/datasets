/*
 * This file is a component of thundr, a software library from 3wks.
 * Read more: http://www.3wks.com.au/thundr
 * Copyright (C) 2015 3wks, <thundr@3wks.com.au>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.threewks.thundr.user.authentication;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.UUID;

import com.threewks.thundr.exception.BaseException;
import com.threewks.thundr.util.Encoder;

import jodd.util.StringPool;

public abstract class BasePasswordAuthentication implements Authentication {
	protected String username;
	protected String hashedpassword;
	protected byte[] salt;
	protected int iterations;
	protected String digest;

	public BasePasswordAuthentication() {
	}

	public BasePasswordAuthentication(String username, String password) {
		this(username, password, 1000, Digests.SHA512);
	}

	public BasePasswordAuthentication(String username, String password, int iterations, String digest) {
		this.username = username;
		this.iterations = iterations;
		this.digest = digest;
		this.salt = salt(8);
		this.hashedpassword = hash(password, salt, iterations, digest);
	}

	protected String hash(String password, byte[] salt, int iterations, String digestAlgorithm) {
		if (password == null) {
			return null;
		}
		try {
			MessageDigest digest = MessageDigest.getInstance(digestAlgorithm);
			digest.update(salt);
			byte[] input = digest.digest(password.getBytes(StringPool.UTF_8));
			for (int i = 0; i < iterations; i++) {
				digest.reset();
				input = digest.digest(input);
			}
			return new Encoder(input).base64().string();
		} catch (Exception e) {
			throw new BaseException(e, "Failed to hash password: %s", e.getMessage());
		}
	}

	protected byte[] salt(int bytes) {
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			random.setSeed(UUID.randomUUID().toString().getBytes());
			byte[] data = new byte[bytes];
			random.nextBytes(data);
			return data;
		} catch (Exception e) {
			throw new BaseException(e, "Failed to generate salt: %s", e.getMessage());
		}
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getHashedpassword() {
		return hashedpassword;
	}

	public void setHashedpassword(String hashedpassword) {
		this.hashedpassword = hashedpassword;
	}

	public byte[] getSalt() {
		return salt;
	}

	public void setSalt(byte[] salt) {
		this.salt = salt;
	}

	public int getIterations() {
		return iterations;
	}

	public void setIterations(int iterations) {
		this.iterations = iterations;
	}

	public String getDigest() {
		return digest;
	}

	public void setDigest(String digest) {
		this.digest = digest;
	}

	@Override
	public boolean validates(String authorisation) {
		return hashedpassword.equals(hash(authorisation, salt, iterations, digest));
	}

	@Override
	public String toString() {
		return "Password for " + username;
	}

	public static class Digests {
		public static final String SHA512 = "SHA-512";
	}

}
