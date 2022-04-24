package com.owtelse.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.owtelse.codec.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;

/**
 * Used to create signed URL's suitable for use with Google's Enterprise API's.
 * Unlike Google's examples this class can be used by Code compiled to at Lang level 1.5 (Java 5)
 * see the examples at https://developers.google.com/maps/documentation/business/webservices
 * to see how to structure suitable URL arguments.
 */
public class UrlSigner {

  private static final Logger LOG = LoggerFactory.getLogger(UrlSigner.class);
  private byte[] key;

/**
 * @param keyString Base64 encoded signing key, as provided by Google when you purchase an Enterprise License.
 * @throws IOException
 */
  public UrlSigner(String keyString) throws IOException {
    // Convert the key from 'web safe' base 64 to binary
    keyString = keyString.replace('-', '+');
    keyString = keyString.replace('_', '/');
    this.key = Base64.decode(keyString);
  }

/**
 * Does the actual signing.
 * @param path
 * @param query
 * @return
 * @throws NoSuchAlgorithmException
 * @throws InvalidKeyException
 * @throws UnsupportedEncodingException
 * @throws URISyntaxException
 */
  public String _doSigning(String path, String query) throws NoSuchAlgorithmException,
    InvalidKeyException, UnsupportedEncodingException, URISyntaxException {
    
    // Retrieve the proper URL components to sign
    String partToSign = path + '?' + query;

    SecretKeySpec sha1Key = new SecretKeySpec(key, "HmacSHA1");

    // Get an HMAC-SHA1 Mac instance and initialize it with the HMAC-SHA1 key
    Mac mac = Mac.getInstance("HmacSHA1");
    mac.init(sha1Key);

    // compute the signature.
    byte[] signature = mac.doFinal(partToSign.getBytes());

    // base 64 encode the binary signature
    String base64Sig = Base64.encode(signature);
    
    // convert the signature to 'web safe' base 64
    base64Sig = base64Sig.replace('+', '-');
    base64Sig = base64Sig.replace('/', '_');
    
    return partToSign + "&signature=" + base64Sig;
  }

/**
 * Constuct a URL and pass it to thismethod and it will create a SHA1 signature Base64 encode it at append it to this URL as a signature parameter
 * for more explanation see Google's doco at https://developers.google.com/maps/documentation/business/webservices.
 *
 * @param url must have your client id as param as well as sensor true or false
 * @return
 * @throws InvalidKeyException
 * @throws NoSuchAlgorithmException
 * @throws UnsupportedEncodingException
 * @throws URISyntaxException
 */
	public String signURL(URL url) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, URISyntaxException {
		String request = _doSigning(url.getPath(), url.getQuery());
	  return url.getProtocol() + "://" + url.getHost() + request;
	}
}
