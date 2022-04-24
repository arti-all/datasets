/**
 * 
 */
package org.shopfoundry.core.security.pki.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RSA Key generator.
 * 
 * @author Bojan Bijelic
 *
 */
public class RSAKeyPairGenerator {

	private final static Logger logger = LoggerFactory
			.getLogger(RSAKeyPairGenerator.class);

	/**
	 * Key size contant for 2048 key size
	 */
	public final static int KEY_SIZE_2048 = 2048;
	
	/**
	 * Generates RSA key pair
	 * 
	 * @param keySize
	 * @return the RSA key pair of specified size
	 * @throws NoSuchAlgorithmException
	 */
	public static KeyPair generateKey(int keySize)
			throws NoSuchAlgorithmException {
		// Get instance of RSA key pair generator
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		// Initialize generator of given key size
		keyPairGenerator.initialize(keySize);
		// Generate key pair
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		if (logger.isTraceEnabled())
			logger.trace(keyPair.toString());

		// Return keypair
		return keyPair;
	}

}
