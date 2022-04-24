package com.github.j3t.ssl.utils;


import com.github.j3t.ssl.utils.types.KeyStoreProvider;
import com.github.j3t.ssl.utils.types.KeyStoreType;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.UUID;

/**
 * A builder pattern style factory to create a {@link KeyStore}.
 *
 * @author j3t
 */
public class KeyStoreBuilder {
    public static KeyStore createWindowsMy() throws GeneralSecurityException, IOException, IllegalAccessException {
        return create().setType(KeyStoreType.WINDOWS_MY).setProvider(KeyStoreProvider.SUN_MSCAPI).build();
    }

    public static KeyStore createWindowsMyFixed() throws GeneralSecurityException, IOException, IllegalAccessException {
        return create().setType(KeyStoreType.WINDOWS_MY).setProvider(KeyStoreProvider.SUN_MSCAPI).setFixAliases(true).build();
    }

    public static KeyStore createWindowsRoot() throws GeneralSecurityException, IOException, IllegalAccessException {
        return create().setType(KeyStoreType.WINDOWS_ROOT).setProvider(KeyStoreProvider.SUN_MSCAPI).setFixAliases(true).build();
    }

    /**
     * Creates a new {@link KeyStoreBuilder} instance.
     *
     * @return {@link KeyStoreBuilder}
     */
    public static KeyStoreBuilder create() {
        return new KeyStoreBuilder();
    }

    private String type;
    private String provider;
    private String path;
    private boolean fixAliases;
    private String libraryPath;
    private char[] password;
    private byte[] key;

    protected KeyStoreBuilder() {
        type = KeyStore.getDefaultType();
        provider = null;
        path = null;
        fixAliases = false;
        libraryPath = null;
        password = null;
    }

    /**
     * Set the name of the security provider. Note that the list of registered providers may be retrieved via the
     * Security.getProviders() method.
     *
     * @param provider the name of the provider
     * @return {@link KeyStoreBuilder}
     * @see KeyStoreProvider
     */
    public KeyStoreBuilder setProvider(String provider) {
        this.provider = provider;
        return this;
    }

    /**
     * Set the type of keystore. Default is {@link KeyStore#getDefaultType()} See Appendix A in the
     * <a href= "../../../technotes/guides/security/crypto/CryptoSpec.html#AppA"> Java Cryptography Architecture API
     * Specification &amp; Reference </a> for information about standard keystore types.
     *
     * @param type the type of keystore.
     * @return {@link KeyStoreBuilder}
     * @see KeyStoreType
     */
    public KeyStoreBuilder setType(String type) {
        this.type = type;
        return this;
    }

    /**
     * Eliminates duplicate alias. Default is <code>false</code>. This parameter should only set to <code>true</code>
     * when the keystore provider is MSCAPI and the keystore contains duplicate aliases. More information about this
     * problem are described <a href="http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6672015">here</a>.
     *
     * @param fixAliases when <code>true</code>, duplicate aliases will be eliminated, otherwise not
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setFixAliases(boolean fixAliases) {
        this.fixAliases = fixAliases;
        return this;
    }

    /**
     * Set the key of the keystore. This is an alternative to {@link #setPath(String)} or
     * {@link #setLibraryPath(String)}.
     *
     * @param key the encoded key as byte array
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setKey(byte[] key) {
        this.key = key;
        return this;
    }

    /**
     * Set the path to the keystore file. This option is an alternative to {@link #setKey(byte[])} or
     * {@link #setLibraryPath(String)}.
     *
     * @param path the path to the keystore file.
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setPath(String path) {
        this.path = path;
        return this;
    }

    /**
     * Set the path to the PKCS11-library. This is an alternative to {@link #setPath(String)} or
     * {@link #setKey(byte[])}.
     *
     * @param libraryPath the path to the PKCS11-library (e.g. /usr/lib/smartcard-reader.lib)
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setLibraryPath(String libraryPath) {
        this.libraryPath = libraryPath;
        return this;
    }

    /**
     * Set the password to access the key store. Default is <code>null</code> (no password required).
     *
     * @param password the password used to check the integrity of the key store, the password used to unlock the key
     *                 store, or null
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setPassword(char[] password) {
        this.password = password;
        return this;
    }

    /**
     * Set the password to access the key store. Default is <code>null</code> (no password required).
     *
     * @param password the password used to check the integrity of the key store, the password used to unlock the key
     *                 store, or null
     * @return {@link KeyStoreBuilder}
     */
    public KeyStoreBuilder setPassword(String password) {
        this.password = password != null ? password.toCharArray() : null;
        return this;
    }

    /**
     * Build a {@link KeyStore}.
     *
     * @return {@link KeyStore}
     * @throws KeyStoreException        if a KeyStoreSpi implementation for the specified type is not available from the
     *                                  specified provider.
     * @throws NoSuchProviderException  if the specified provider is not registered in the security provider list.
     * @throws IllegalArgumentException if the provider name is null or empty.
     * @throws IllegalAccessException   if the {@link #setFixAliases(boolean)} is set to <code>true</code>
     * @throws IOException              if there is an I/O or format problem with the keystore data, if a password is
     *                                  required but not given, or if the given password was incorrect. If the error is
     *                                  due to a wrong password, the cause of the IOException should be an
     *                                  UnrecoverableKeyException
     * @throws NoSuchAlgorithmException if the algorithm used to check the integrity of the keystore cannot be found
     * @throws CertificateException     if any of the certificates in the keystore could not be loaded
     */
    public KeyStore build() throws GeneralSecurityException, IOException, IllegalAccessException {
        KeyStore keyStore = null;

        if (libraryPath != null)
            setUpPKCS11ProviderWithLibrary();

        if (provider != null)
            keyStore = KeyStore.getInstance(type, provider);
        else
            keyStore = KeyStore.getInstance(type);

        if (path != null)
            keyStore.load(new FileInputStream(path), password);
        else if (key != null)
            keyStore.load(new ByteArrayInputStream(key), password);
        else
            keyStore.load(null, password);

        if (fixAliases)
            fixKeyStoreAliases(keyStore);

        return keyStore;
    }

    /**
     * Build a {@link KeyStore} without catching exceptions.
     *
     * @return {@link KeyStore}
     * @throws IllegalStateException if the build failed
     * @see #build()
     */
    public KeyStore buildUnsecure() throws IllegalStateException {
        try {
            return build();
        } catch (Exception e) {
            throw new IllegalStateException("build failed!", e);
        }
    }

    private void setUpPKCS11ProviderWithLibrary() throws IOException {
        String name = UUID.randomUUID().toString();

        registerProvider(name, libraryPath);

        setProvider("SunPKCS11-" + name);
    }

    private void registerProvider(String name, String library) throws IOException {
        byte[] config = String.format("name = %s\nlibrary=%s\n", name, library).getBytes();

        Security.addProvider(new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(config)));
    }

    /**
     * This method eliminates duplicate aliases. This is sometimes required, read more
     * about this problem <a href="http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6672015">here</a>.
     *
     * @param keyStore {@link KeyStore}
     * @throws IllegalStateException - if the fix can't processed
     */
    private void fixKeyStoreAliases(KeyStore keyStore) throws IllegalStateException {
        try {
            Field field = keyStore.getClass().getDeclaredField("keyStoreSpi");
            field.setAccessible(true);
            KeyStoreSpi keyStoreVeritable = (KeyStoreSpi) field.get(keyStore);

            if ("sun.security.mscapi.KeyStore$MY".equals(keyStoreVeritable.getClass().getName())) {
                String alias;
                String hashCode;
                X509Certificate[] certificates;

                field = keyStoreVeritable.getClass().getEnclosingClass().getDeclaredField("entries");
                field.setAccessible(true);

                if (field.get(keyStoreVeritable) instanceof Collection)
                    for (Object entry : (Collection<?>) field.get(keyStoreVeritable)) {
                        field = entry.getClass().getDeclaredField("certChain");
                        field.setAccessible(true);
                        certificates = (X509Certificate[]) field.get(entry);

                        hashCode = certificates[0].hashCode() + "";

                        field = entry.getClass().getDeclaredField("alias");
                        field.setAccessible(true);
                        alias = (String) field.get(entry);

                        if (!alias.equals(hashCode))
                            field.set(entry, alias.concat(" - ").concat(hashCode));
                    }
            }
        } catch (Exception e) {
            throw new IllegalStateException("fix keystore aliases failed!", e);
        }
    }

}
