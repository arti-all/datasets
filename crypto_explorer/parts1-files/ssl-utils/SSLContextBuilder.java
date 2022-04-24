package com.github.j3t.ssl.utils;


import com.github.j3t.ssl.utils.strategy.KeyManagerStrategy;
import com.github.j3t.ssl.utils.strategy.StrategyKeyManager;
import com.github.j3t.ssl.utils.strategy.StrategyTrustManager;
import com.github.j3t.ssl.utils.strategy.TrustManagerStrategy;
import com.github.j3t.ssl.utils.types.SslProtocol;

import javax.net.ssl.*;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

/**
 * A builder pattern style factory for the creation of {@link SSLContext} objects.
 *
 * @author j3t
 */
public class SSLContextBuilder {
    private KeyStore keyStore;
    private char[] keyStorePassword;
    private String keyManagerAlgorithm;
    private KeyManagerStrategy keyManagerStrategy;

    private KeyStore trustStore;
    private String trustManagerAlgorithm;
    private TrustManagerStrategy trustManagerStrategy;

    private SecureRandom secureRandomGenerator;
    private String protocol;

    /**
     * Creates a new {@link SSLContextBuilder} instance.
     *
     * @return {@link SSLContextBuilder}
     */
    public static SSLContextBuilder create() {
        return new SSLContextBuilder();
    }

    protected SSLContextBuilder() {
        keyStore = null;
        keyStorePassword = null;
        keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
        keyManagerStrategy = null;

        trustStore = null;
        trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        trustManagerStrategy = null;

        secureRandomGenerator = null;
        protocol = null;
    }

    /**
     * Set up the trust store. This store contains all trusted peers.<br>
     * <br>
     * Default: none
     *
     * @param trustStore the trust store (e.g. {@link KeyStoreBuilder#createWindowsRoot()})
     * @return this @link SSLContextBuilder}
     */
    public SSLContextBuilder setTrustStore(KeyStore trustStore) {
        this.trustStore = trustStore;
        return this;
    }

    /**
     * Set up the algorithm of the TrustManagerFactory.<br>
     * <br>
     * Default: {@link TrustManagerFactory#getDefaultAlgorithm()}
     *
     * @param trustManagerAlgorithm the algorithm name of the TrustManagerFactory
     * @return this @link SSLContextBuilder}
     */
    public SSLContextBuilder setTrustManagerAlgorithm(String trustManagerAlgorithm) {
        this.trustManagerAlgorithm = trustManagerAlgorithm;
        return this;
    }

    /**
     * Set up a strategy to establish trustworthiness of certificates independent of the trustworthiness in the trust
     * store. This can be used to override the standard certificate verification process.<br>
     * <br>
     * Default: none
     *
     * @param trustManagerStrategy the alias selection strategy
     * @return this @link SSLContextBuilder}
     */
    public SSLContextBuilder setTrustManagerStrategy(TrustManagerStrategy trustManagerStrategy) {
        this.trustManagerStrategy = trustManagerStrategy;
        return this;
    }

    /**
     * Set up the key store. This store contains private key (at least one) to authenticate your self.<br>
     * <br>
     * Default: none
     *
     * @param keyStore the key store (e.g. {@link KeyStoreBuilder#createWindowsMy()})
     * @return this @link SSLContextBuilder}
     */
    public SSLContextBuilder setKeyStore(KeyStore keyStore) {
        this.keyStore = keyStore;
        return this;
    }

    /**
     * Set up the key store password.<br>
     * <br>
     * Default: none
     *
     * @param keyStorePassword the key store password (e.g. changeit)
     * @return this @link SSLContextBuilder}
     */
    public SSLContextBuilder setKeyStorePassword(char[] keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
        return this;
    }

    /**
     * Set up the key store password.<br>
     * <br>
     * Default: none
     *
     * @param keyStorePassword the key store password (e.g. changeit)
     * @return this @link SSLContextBuilder}
     */
    public SSLContextBuilder setKeyStorePassword(String keyStorePassword) {
        setKeyStorePassword(keyStorePassword != null ? keyStorePassword.toCharArray() : null);
        return this;
    }

    /**
     * Set up the algorithm name of the KeyManagerFactory.<br>
     * <br>
     * Default: {@link KeyManagerFactory#getDefaultAlgorithm()}
     *
     * @param keyManagerAlgorithm the algorithm name of the KeyManagerFactory
     * @return this @link SSLContextBuilder}
     */
    public SSLContextBuilder setKeyManagerAlgorithm(String keyManagerAlgorithm) {
        this.keyManagerAlgorithm = keyManagerAlgorithm;
        return this;
    }

    /**
     * Set up a strategy which alias is to select during the authentication, no matter the alias exists or the
     * certificate is valid. This can be used to override the standard authentication process.<br>
     * <br>
     * Default: none
     *
     * @param keyManagerStrategy the strategy a alias is selected
     * @return {@link SSLContextBuilder}
     */
    public SSLContextBuilder setKeyManagerStrategy(KeyManagerStrategy keyManagerStrategy) {
        this.keyManagerStrategy = keyManagerStrategy;
        return this;
    }

    /**
     * Set up the protocol.<br>
     * <br>
     * Default: Java 8 TLSv1.2, Java 7 TLSv1.1 otherwise TLSv1.0
     *
     * @param protocol the protocol (e.g. SSLv3, TLSv1.1, ...)
     * @return this @link SSLContextBuilder}
     */
    public SSLContextBuilder setProtocol(String protocol) {
        this.protocol = protocol;
        return this;
    }

    /**
     * Set up the random number generator.<br>
     * <br>
     * Default: {@link SecureRandom}
     *
     * @param secureRandomGenerator the random number generator
     * @return this {@link SSLContextBuilder}
     */
    public SSLContextBuilder setSecureRandomGenerator(SecureRandom secureRandomGenerator) {
        this.secureRandomGenerator = secureRandomGenerator;
        return this;
    }

    /**
     * Build the {@link SSLContext}.
     *
     * @return {@link SSLContext}, shouldn't be <code>null</code>
     * @throws GeneralSecurityException if the build failed!
     * @throws IOException              if the build failed!
     */
    public SSLContext build() throws GeneralSecurityException, IOException {
        SSLContext ctx = createSSLContext();
        ctx.init(createKeyManagers(), createTrustManagers(), createSecureRandomGenerator());

        return ctx;
    }

    protected SSLContext createSSLContext() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (protocol == null)
            return SSLContext.getInstance(getProtocolBestEffort());

        return SSLContext.getInstance(protocol);
    }

    protected String getProtocolBestEffort() {
        if (EnvironmentHelper.isJava7OrHigher())
            return SslProtocol.TLSv12;

        return SslProtocol.TLSv10;
    }

    protected KeyManager[] createKeyManagers() throws GeneralSecurityException {
        if (keyStore == null)
            return null;

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(keyManagerAlgorithm);
        kmf.init(keyStore, keyStorePassword);

        KeyManager[] keyManagers = kmf.getKeyManagers();

        if (keyManagerStrategy != null)
            keyManagers = addStrategy(keyManagers);

        return keyManagers;
    }

    protected TrustManager[] createTrustManagers() throws NoSuchAlgorithmException, KeyStoreException {
        TrustManagerFactory instance = TrustManagerFactory.getInstance(trustManagerAlgorithm);
        instance.init(trustStore);

        TrustManager[] trustManagers = instance.getTrustManagers();

        if (trustManagerStrategy != null)
            trustManagers = addStrategy(trustManagers);

        return trustManagers;
    }

    protected SecureRandom createSecureRandomGenerator() {
        return secureRandomGenerator != null ? secureRandomGenerator : new SecureRandom();
    }

    protected KeyManager[] addStrategy(KeyManager[] keyManagers) {
        KeyManager[] kms = new KeyManager[keyManagers.length];

        for (int i = 0; i < keyManagers.length; i++)
            kms[i] = new StrategyKeyManager((X509KeyManager) keyManagers[i], keyManagerStrategy);

        return kms;
    }

    protected TrustManager[] addStrategy(TrustManager[] trustManagers) {
        TrustManager[] tms = new TrustManager[trustManagers.length];

        for (int i = 0; i < trustManagers.length; i++)
            tms[i] = new StrategyTrustManager((X509TrustManager) trustManagers[i], trustManagerStrategy);

        return tms;
    }

}
