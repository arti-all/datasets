package net.trajano.commons.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This wraps an input stream to provide a digest.
 * 
 * @author trajano
 * 
 */
public class DigestInputStream extends FilterInputStream {
	/**
	 * Message digest.
	 */
	private final MessageDigest digest;
	private byte[] digestValue = null;

	public DigestInputStream(final InputStream in, final String algorithm)
			throws NoSuchAlgorithmException {
		super(in);
		digest = MessageDigest.getInstance(algorithm);

	}

	@Override
	public void close() throws IOException {
		in.close();
		digestValue = digest.digest();
	}

	/**
	 * This will return the digest value. This will return <code>null</code> if
	 * the stream is not closed.
	 * 
	 * @return
	 */
	public byte[] digest() {
		return digestValue;
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
