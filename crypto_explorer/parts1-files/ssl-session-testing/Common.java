/*
 * Copyright 2018 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.util.Enumeration;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class Common {

    private static KeyStore loadKeyStore(final String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("jks");
        try (FileInputStream fis = new FileInputStream(path)) {
            keyStore.load(fis, "Elytron".toCharArray());
        }

        return keyStore;
    }

    private static KeyManager[] getKeyManager(final String path) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(loadKeyStore(path), "Elytron".toCharArray());
        return keyManagerFactory.getKeyManagers();
    }

    private static TrustManager[] getTrustManagers(final String path) throws Exception {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(loadKeyStore(path));
        return trustManagerFactory.getTrustManagers();
    }

    public static SSLContext createClientSSLContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(getKeyManager("src/main/resources/ladybird.keystore"), getTrustManagers("src/main/resources/ca.truststore"), null);

        return sslContext;
    }

    public static SSLContext createServerSSLContext() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(getKeyManager("src/main/resources/scarab.keystore"), getTrustManagers("src/main/resources/ca.truststore"), null);

        return sslContext;
    }

    public static void outputSessionInfo(final SSLContext sslContext, final boolean server) {
        SSLSessionContext sessionContext = server ? sslContext.getServerSessionContext() : sslContext.getClientSessionContext();

        System.out.println("\n * * SSL Session Information - START * *\n");
        Enumeration<byte[]> sessionIds = sessionContext.getIds();
        int position = 1;
        while (sessionIds.hasMoreElements()) {
            byte[] currentId = sessionIds.nextElement();
            System.out.println(position++ + " {" + new String(currentId) + "}");
        }
        System.out.println(position - 1 + " Sessions");

        System.out.println("\n * * SSL Session Information - END * *\n");

    }

}
