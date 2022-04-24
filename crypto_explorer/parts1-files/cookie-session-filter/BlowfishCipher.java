package jp.sf.amateras.cookiesession.cipher;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterConfig;

import jp.sf.amateras.cookiesession.exception.ChiperException;
import jp.sf.amateras.cookiesession.exception.InitializationException;
import jp.sf.amateras.cookiesession.util.StringUtil;

import org.apache.commons.codec.binary.Hex;

public class BlowfishCipher implements jp.sf.amateras.cookiesession.cipher.Cipher {

	private static final String CONFIG_KEY = "key";

	private String key;

	public void init(FilterConfig config){
		String key = config.getInitParameter(CONFIG_KEY);
		if(StringUtil.isEmpty(key)){
			throw new InitializationException("Blowfish key has not been specified.");
		}
		this.key = key;
	}

	public String encrypt(String value) {
		try {
			SecretKeySpec sksSpec = new SecretKeySpec(key.getBytes(), "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.ENCRYPT_MODE, sksSpec);
			byte[] encrypted = cipher.doFinal(value.getBytes());

			return new String(Hex.encodeHex(encrypted));

		} catch(Exception ex){
			throw new ChiperException(ex);
		}
	}

	public String decrypt(String value) {
		try {
			byte[] encrypted = Hex.decodeHex(value.toCharArray());

			SecretKeySpec sksSpec = new SecretKeySpec(key.getBytes(), "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, sksSpec);
			byte[] decrypted = cipher.doFinal(encrypted);

			return new String(decrypted);

		} catch(Exception ex){
			throw new ChiperException(ex);
		}
	}

}
