package com.github.felfert.sslutils;

import java.io.IOException;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.KeyManagementException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An SSLSocketFactory for LDAP which trusts all certificates.
 */
public final class TrustAllSSLSocketFactory {

    /** Our logger. */
    static final Logger LOGGER = LoggerFactory.getLogger(TrustAllSSLSocketFactory.class);

    private final SSLSocketFactory ssf;

    /**
     * Create a new instance.
     * @throws NoSuchAlgorithmException if the SSLContext.getInstance() call fails.
     * @throws KeyManagementException if the SSLContext.init() call fails.
     */
    public TrustAllSSLSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
        final SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[] {new TrustAllManager()}, new SecureRandom());
        ssf = ctx.getSocketFactory();
    }

    /**
     * Creates a connected socket.
     * @param host The host name to connect to.
     * @param port The port to connect to.
     * @return an SSLSocket, configured to ignore peer certificates.
     * @throws IOException if an error happens.
     */
    public Socket createSocket(final String host, final int port) throws IOException {
        LOGGER.warn("Using insecure TrustAllSSLSocketFactory!");
        return ssf.createSocket(host, port);
    }

    /**
     * Creates an unconnected socket.
     * @return an SSLSocket, configured to ignore peer certificates.
     * @throws IOException if an error happens.
     */
    public Socket createSocket() throws IOException {
        LOGGER.warn("Using insecure TrustAllSSLSocketFactory!");
        return ssf.createSocket();
    }

    /**
     * Fetches the underlying SSLSocketFactory.
     * @return The underlying SSLSocketFactory.
     */
    public SSLSocketFactory getRealSSLSocketFactory() {
        LOGGER.warn("Using insecure TrustAllSSLSocketFactory!");
        return ssf;
    }

    /**
     * Fetches a new TrustAllSSLSocketFactory.
     * @return A new instance of this factory.
     * @throws NoSuchAlgorithmException if the SSLContext.getInstance() call fails.
     * @throws KeyManagementException if the SSLContext.init() call fails.
     */
    public static Object getDefault() throws NoSuchAlgorithmException, KeyManagementException {
        return new TrustAllSSLSocketFactory();
    }
}
