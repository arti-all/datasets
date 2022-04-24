package bg.bas.iinf.sinus.wicket.common;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * obsht Util klas
 * @author hok
 *
 */
public class Util {

	private static final Log log = LogFactory.getLog(Util.class);

	public static byte[] generateSha(String input) {
		MessageDigest sha = null;
		try {
			sha = MessageDigest.getInstance("SHA-256");
			sha.update(input.getBytes("UTF-8")); // tqbva da e explicitno zadadneo (inache polzva defaultnoto na sistemata
		} catch (NoSuchAlgorithmException e) {
			log.error(e);
			return null;
		} catch (UnsupportedEncodingException e) {
			log.error(e);
	        return null;
        }

		return sha.digest();
	}
}
