package net.trajano.commons.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;

/**
 * This wraps an input stream to allow verification using a digest value.
 * 
 * @author trajano
 * 
 */
public class VerifyingInputStream extends FilterInputStream {
	/**
	 * Message digest.
	 */
	private final MessageDigest digest;
	/**
	 * Expected digest value.
	 */

	private final byte[] expected;

	public VerifyingInputStream(final InputStream in,
			final MessageDigest digest, final byte[] expected) {
		super(in);
		this.digest = digest;
		this.expected = expected;
	}

	public VerifyingInputStream(final InputStream in, final String algorithm,
			final byte[] expected) throws NoSuchAlgorithmException {
		super(in);
		digest = MessageDigest.getInstance(algorithm);
		this.expected = expected;
	}

	/**
	 * Upon closing the file the digest is compared. If it does not match an
	 * {@link IOException} is thrown.
	 */
	@Override
	public void close() throws IOException {
		in.close();
		final byte[] actual = digest.digest();
		if (!MessageDigest.isEqual(actual, expected)) {
			throw new IOException(String.format(
					"Digest value mismatch expected=%s actual=%s",
					DatatypeConverter.printHexBinary(expected),
					DatatypeConverter.printHexBinary(actual)));
		}
	}

	@Override
	public int read() throws IOException {
		final int c = in.read();
		digest.update((byte) c);
		return c;
	}

	@Override
	public int read(final byte[] b) throws IOException {
		final int c = in.read(b);
		digest.update(b);
		return c;
	}

	@Override
	public int read(final byte[] b, final int off, final int len)
			throws IOException {
		final int c = in.read(b, off, len);
		digest.update(b, off, len);
		return c;
	}

}
