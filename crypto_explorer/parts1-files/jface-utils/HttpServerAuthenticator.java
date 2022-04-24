package it.albertus.net.httpserver;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

import com.sun.net.httpserver.BasicAuthenticator;
import com.sun.net.httpserver.HttpExchange;

import it.albertus.jface.JFaceMessages;
import it.albertus.net.httpserver.config.IAuthenticatorConfig;
import it.albertus.util.StringUtils;
import it.albertus.util.logging.LoggerFactory;

@SuppressWarnings("restriction")
public class HttpServerAuthenticator extends BasicAuthenticator {

	private static final Logger logger = LoggerFactory.getLogger(HttpServerAuthenticator.class);

	private static final String DEFAULT_CHARSET_NAME = "UTF-8";

	private final IAuthenticatorConfig configuration;
	private Charset charset = Charset.forName(DEFAULT_CHARSET_NAME);

	private final ThreadLocal<HttpExchange> exchanges = new ThreadLocal<HttpExchange>();

	public HttpServerAuthenticator(final IAuthenticatorConfig configuration) {
		super(configuration.getRealm());
		this.configuration = configuration;
	}

	@Override
	public Result authenticate(final HttpExchange exchange) {
		try {
			exchanges.set(exchange); // used in checkCredentials(...)
			return super.authenticate(exchange);
		}
		finally {
			exchanges.remove();
		}
	}

	@Override
	public boolean checkCredentials(final String specifiedUsername, final String specifiedPassword) {
		try {
			if (specifiedUsername == null || specifiedUsername.isEmpty() || specifiedPassword == null || specifiedPassword.isEmpty()) {
				return fail();
			}

			final char[] expectedPassword = getConfiguration().getPassword(specifiedUsername);
			if (expectedPassword != null && expectedPassword.length > 0 && checkPassword(specifiedPassword, expectedPassword)) {
				return true;
			}
			else {
				final HttpExchange exchange = exchanges.get();
				logger.log(Level.parse(getConfiguration().getFailureLoggingLevel()), JFaceMessages.get("err.httpserver.authentication"), new Object[] { specifiedUsername, specifiedPassword, exchange != null ? exchange.getRemoteAddress() : null });
				return fail();
			}
		}
		catch (final Exception e) {
			logger.log(Level.SEVERE, e.toString(), e);
			return fail();
		}
	}

	protected boolean checkPassword(final String provided, final char[] expected) {
		final char[] computed;
		if (StringUtils.isNotBlank(configuration.getPasswordHashAlgorithm())) {
			computed = DatatypeConverter.printHexBinary(newMessageDigest(configuration.getPasswordHashAlgorithm().trim()).digest(provided.getBytes(charset))).toLowerCase().toCharArray();
		}
		else {
			computed = provided.toCharArray();
		}

		boolean equal = true;
		if (computed.length != expected.length) {
			equal = false;
		}
		for (int i = 0; i < 0x400; i++) {
			if (computed[i % computed.length] != expected[i % expected.length]) {
				equal = false;
			}
		}
		return equal;
	}

	protected boolean fail() {
		try {
			TimeUnit.MILLISECONDS.sleep(configuration.getFailDelayMillis());
		}
		catch (final InterruptedException e) {
			logger.log(Level.FINE, e.toString(), e);
			Thread.currentThread().interrupt();
		}
		return false;
	}

	public Charset getCharset() {
		return charset;
	}

	public void setCharset(final Charset charset) {
		this.charset = charset;
	}

	protected IAuthenticatorConfig getConfiguration() {
		return configuration;
	}

	private static MessageDigest newMessageDigest(final String algorithm) {
		try {
			return MessageDigest.getInstance(algorithm);
		}
		catch (final NoSuchAlgorithmException e) {
			throw new IllegalArgumentException(algorithm, e);
		}
	}

}
