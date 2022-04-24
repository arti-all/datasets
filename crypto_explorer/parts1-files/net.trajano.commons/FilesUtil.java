package net.trajano.commons.io;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import net.trajano.commons.filevisitor.RemoveEmptyFoldersVisitor;
import net.trajano.commons.filevisitor.RemoveFoldersVisitor;

public final class FilesUtil {
	public static final Path deleteEmptyFolders(final Path path)
			throws IOException {
		return Files.walkFileTree(path, new RemoveEmptyFoldersVisitor());
	}

	public static final Path deleteFolders(final Path path) throws IOException {
		return Files.walkFileTree(path, new RemoveFoldersVisitor());
	}

	/**
	 * Verifies if the expected digest matches the calculated digest for a given
	 * {@link InputStream}.
	 * 
	 * @param path
	 *            path of the file to verify.
	 * @param algorithm
	 *            algorithm to use
	 * @param expected
	 *            expected digest
	 * @return <code>true</code> if the digests match, <code>false</code>
	 *         otherwise.
	 * 
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a MessageDigestSpi implementation for
	 *             the specified algorithm.
	 * @throws IOException
	 *             if an I/O error occurs.
	 */
	public static final boolean verifyDigest(final InputStream in,
			final String algorithm, final byte[] expected)
			throws NoSuchAlgorithmException, IOException {
		final DigestInputStream dis = new DigestInputStream(in, MessageDigest
				.getInstance(algorithm));
		while (dis.read() != -1) {
		}
		dis.close();
		return MessageDigest.isEqual(expected, dis.getMessageDigest().digest());
	}

	/**
	 * Verifies if the expected digest matches the calculated digest for a given
	 * path.
	 * 
	 * @param path
	 *            path of the file to verify.
	 * @param algorithm
	 *            algorithm to use
	 * @param expected
	 *            expected digest
	 * @return <code>true</code> if the digests match, <code>false</code>
	 *         otherwise.
	 * 
	 * @throws NoSuchAlgorithmException
	 *             if no Provider supports a MessageDigestSpi implementation for
	 *             the specified algorithm.
	 * @throws IOException
	 *             if an I/O error occurs.
	 */
	public static final boolean verifyDigest(final Path path,
			final String algorithm, final byte[] expected)
			throws NoSuchAlgorithmException, IOException {
		return verifyDigest(Files.newInputStream(path), algorithm, expected);
	}

	/**
	 * Prevent instantiation of utility class
	 */
	private FilesUtil() {
	}
}