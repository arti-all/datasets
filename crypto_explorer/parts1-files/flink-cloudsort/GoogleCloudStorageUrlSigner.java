package org.apache.flink.cloudsort.util;

import org.apache.commons.codec.binary.Base64;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;

/**
 * Utility functions to sign Google Cloud Storage URLs.
 */
public class GoogleCloudStorageUrlSigner {

	private GoogleCloudStorageUrlSigner() {}

	// private key from a service account saved in /src/main/resources
	private static final String KEY_FILENAME = "/privatekey.p12";

	// the default password when creating private keys
	private static final String KEY_PASSWORD = "notasecret";

	public static String signString(String stringToSign) throws Exception {
		// load key
		PrivateKey key = loadKeyFromPkcs12(KEY_FILENAME, KEY_PASSWORD.toCharArray());

		// sign data
		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initSign(key);
		signer.update(stringToSign.getBytes("UTF-8"));
		byte[] rawSignature = signer.sign();

		return new String(Base64.encodeBase64(rawSignature, false), "UTF-8");
	}

	private static PrivateKey loadKeyFromPkcs12(String filename, char[] password) throws Exception {
		InputStream is = GoogleCloudStorageUrlSigner.class.getResourceAsStream(filename);

		KeyStore ks = KeyStore.getInstance("PKCS12");

		ks.load(is, password);
		return (PrivateKey) ks.getKey("privatekey", password);
	}
}
