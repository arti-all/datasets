package com.vanillaci.slave.util;

import com.vanillaci.slave.exceptions.UnhandledException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

/**
 * User: Joel Johnson
 * Date: 12/7/12
 * Time: 5:41 PM
 */
public class HashUtils {
	public static String sha(File file) throws FileNotFoundException {
		try {
			FileInputStream fileInputStream = new FileInputStream(file);
			try {
				DigestInputStream digestInputStream = new DigestInputStream(fileInputStream, MessageDigest.getInstance("SHA"));
				byte[] buffer = new byte[8192];
				int read;
				do {
					read = digestInputStream.read(buffer);
					//just read the whole file
				} while(read > -1 && read != buffer.length);

				byte[] digest = digestInputStream.getMessageDigest().digest();

				Formatter formatter = new Formatter();
				for (byte b : digest) {
					formatter.format("%02x", b);
				}
				return formatter.toString();

			} catch (NoSuchAlgorithmException e) {
				throw new UnhandledException(e);
			} finally {
				fileInputStream.close();
			}
		} catch (IOException e) {
			throw new UnhandledException(e);
		}
	}
}
