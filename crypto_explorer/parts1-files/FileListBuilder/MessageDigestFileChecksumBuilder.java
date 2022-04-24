package au.id.wolfe.recursivefilelister.digest;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * An implementation of {@link FileChecksumBuilder} which streams the content of each file to a {@link
 * java.security.MessageDigest} to generate a checksum.
 */
public class MessageDigestFileChecksumBuilder extends AbstractFileChecksumBuilder {

    /**
     * The {@link java.security.MessageDigest} instance.
     */
    private final MessageDigest messageDigest;

    /**
     * Build a new instance of {@link MessageDigestFileChecksumBuilder}.
     *
     * @param algorithm the algorithm used to compute checksum digests.
     * @throws NoSuchAlgorithmException in case the given is not supported.
     */
    public MessageDigestFileChecksumBuilder(String algorithm) throws NoSuchAlgorithmException {
        super(algorithm);
        Security.addProvider(new BouncyCastleProvider());
        messageDigest = MessageDigest.getInstance(algorithm);
    }

    /**
     * {@inheritDoc}
     */
    public String calculate(File file) throws FileChecksumException {

        try {

            messageDigest.reset();

            if (!file.canRead()){
                return "CANT READ FILE";
            }

            // Obtain a channel
            ReadableByteChannel channel = new FileInputStream(file).getChannel();

            ByteBuffer buf = ByteBuffer.allocate(DEFAULT_STREAM_BUFFER_SIZE);

            int numRead;

            while ((numRead = channel.read(buf)) != -1){

                messageDigest.update(buf.array(), 0, numRead);
                buf.rewind();
            }

            logger.debug(String.format("checksum for file = %s, length = %d", file.getName(), file.length()));

            return new String(Hex.encode(messageDigest.digest()));
        } catch (IOException e) {
            throw new FileChecksumException(e.getMessage());
        }

    }

}
