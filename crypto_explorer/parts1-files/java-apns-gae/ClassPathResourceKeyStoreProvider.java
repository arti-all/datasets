package apns.keystore;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class ClassPathResourceKeyStoreProvider implements KeyStoreProvider {

    private final String mPath;
    private final String mType;
    private final char[] mPassword;

    public ClassPathResourceKeyStoreProvider(String path, String type, char[] keyStorePassword) {
        if (path == null) {
            throw new IllegalArgumentException("path must not be null");
        }
        if (type == null) {
            throw new IllegalArgumentException("type must not be null");
        }
        if (keyStorePassword == null) {
            throw new IllegalArgumentException("keyStorePassword must not be null");
        }
        mPath = path;
        mType = type;
        mPassword = keyStorePassword;
    }

    @Override
    public KeyStore getKeyStore() throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance(mType);

        try (InputStream is = getKeyStoreInputStream()) {
            keyStore.load(is, mPassword);
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new KeyStoreException("Could not load keystore", e);
        }
        return keyStore;
    }

    private InputStream getKeyStoreInputStream() throws KeyStoreException {
        InputStream is = getClass().getClassLoader().getResourceAsStream(mPath);
        if (is == null) {
            throw new KeyStoreException(String.format("Could not find keystore at [%s]", mPath));
        }
        return is;
    }

    @Override
    public char[] getKeyStorePassword() {
        return mPassword;
    }

}