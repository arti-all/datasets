package net.trajano.commons.io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This wraps an input stream to provide a digest.
 * 
 * @author trajano
 * 
 */
public class DigestOutputStream extends FilterOutputStream {
	/**
	 * Message digest.
	 */
	private final MessageDigest digest;
	private byte[] digestValue = null;

	public DigestOutputStream(final OutputStream out, final String algorithm)
			throws NoSuchAlgorithmException {
		super(out);
		digest = MessageDigest.getInstance(algorithm);
	}

	@Override
	public void close() throws IOException {
		out.close();
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
