package net.trajano.commons.io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.xml.bind.DatatypeConverter;

/**
 * This wraps an input stream to provide a digest.
 * 
 * @author trajano
 * 
 */
public class VerifyingOutputStream extends FilterOutputStream {
	/**
	 * Message digest.
	 */
	private final MessageDigest digest;
	/**
	 * Expected digest value.
	 */
	private final byte[] expected;

	public VerifyingOutputStream(final OutputStream out,
			final MessageDigest digest, final byte[] expected)
			throws NoSuchAlgorithmException {
		super(out);
		this.digest = digest;
		this.expected = expected;
	}

	public VerifyingOutputStream(final OutputStream out,
			final String algorithm, final byte[] expected)
			throws NoSuchAlgorithmException {
		super(out);
		digest = MessageDigest.getInstance(algorithm);
		this.expected = expected;
	}

	/**
	 * Upon closing the file the digest is compared. If it does not match an
	 * {@link IOException} is thrown.
	 */
	@Override
	public void close() throws IOException {
		out.close();
		final byte[] actual = digest.digest();
		if (!MessageDigest.isEqual(actual, expected)) {
			throw new IOException(String.format(
					"Digest value mismatch expected=%s actual=%s",
					DatatypeConverter.printHexBinary(expected),
					DatatypeConverter.printHexBinary(actual)));
		}
	}

	@Override
	public void write(final byte[] b) throws IOException {
		digest.update(b);
		out.write(b);
	}

	@Override
	public void write(final byte[] b, final int off, final int len)
			throws IOException {
		digest.update(b, off, len);
		out.write(b, off, len);
	}

	@Override
	public void write(final int b) throws IOException {
		digest.update((byte) b);
		out.write(b);
	}
}
