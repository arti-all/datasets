/*
 * Copyright © 2014 Cask Data, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package co.cask.http;

import com.google.common.io.Closeables;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;

/**
 * A class that encapsulates SSL Certificate Information.
 */
public class SSLHandlerFactory {

    private static final String protocol = "TLS";
    private final SSLContext serverContext;
    private boolean needClientAuth;

    public SSLHandlerFactory(SSLConfig sslConfig) {
        String algorithm = Security.getProperty("ssl.KeyManagerFactory.algorithm");
        if (algorithm == null) {
            algorithm = "SunX509";
        }
        try {
            KeyStore ks = getKeyStore(sslConfig.getKeyStore(), sslConfig.getKeyStorePassword());
            // Set up key manager factory to use our key store
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(algorithm);
            kmf.init(ks, sslConfig.getCertificatePassword() != null ? sslConfig.getCertificatePassword().toCharArray()
                    : sslConfig.getKeyStorePassword().toCharArray());
            KeyManager[] keyManagers = kmf.getKeyManagers();
            TrustManager[] trustManagers = null;
            if (sslConfig.getTrustKeyStore() != null) {
                this.needClientAuth = true;
                KeyStore tks = getKeyStore(sslConfig.getTrustKeyStore(), sslConfig.getTrustKeyStorePassword());
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(algorithm);
                tmf.init(tks);
                trustManagers = tmf.getTrustManagers();
            }
            serverContext = SSLContext.getInstance(protocol);
            serverContext.init(keyManagers, trustManagers, null);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to initialize the server-side SSLContext", e);
        }
    }

    private static KeyStore getKeyStore(File keyStore, String keyStorePassword) throws IOException {
        KeyStore ks = null;
        InputStream is = new FileInputStream(keyStore);
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(is, keyStorePassword.toCharArray());
        } catch (Exception ex) {
            if (ex instanceof RuntimeException) {
                throw ((RuntimeException) ex);
            }
            throw new IOException(ex);
        } finally {
            Closeables.closeQuietly(is);
        }
        return ks;
    }

    /**
     * @return instance of {@code SslHandler}
     */
    public SslHandler create() {
        SSLEngine engine = serverContext.createSSLEngine();
        engine.setNeedClientAuth(needClientAuth);
        engine.setUseClientMode(false);
        return new SslHandler(engine);
    }
}
