/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.web.comet;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.util.Random;
import javax.net.ssl.*;

/**
 * {@code CometServletSSLClientTest}
 * <p/>
 *
 * Created on May 30, 2012 at 9:52:33 AM
 *
 * @author <a href="mailto:nbenothm@redhat.com">Nabil Benothman</a>
 */
public class CometServletSSLClientTest extends CometServletClientTest {

    private static final TrustManager[] trustAllCerts = new TrustManager[]{
        new X509TrustManager() {

            @Override
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }

            @Override
            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }
        }
    };

    /**
     * Create a new instance of {@code CometServletSSLClientTest}
     *
     * @param delay
     */
    public CometServletSSLClientTest(int delay) {
        super(delay);
    }

    /**
     * Create a new instance of {@code CometServletSSLClientTest}
     *
     * @param url
     * @param delay
     */
    public CometServletSSLClientTest(URL url, int delay) {
        super(url, delay);
    }

    /**
     * Create a new instance of {@code CometServletSSLClientTest}
     *
     * @param d_max
     * @param delay
     */
    public CometServletSSLClientTest(int d_max, int delay) {
        super(d_max, delay);
    }

    /**
     * Create a new instance of {@code CometServletSSLClientTest}
     *
     * @param url
     * @param d_max
     * @param delay
     * @throws Exception
     */
    public CometServletSSLClientTest(URL url, int d_max, int delay) throws Exception {
        super(url, d_max, delay);
    }

    @Override
    public void connect() throws Exception {
        try {
            SSLContext sslCtx = SSLContext.getInstance("TLS");
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            KeyStore ks = KeyStore.getInstance("JKS");
            String fileName = System.getProperty("javax.net.ssl.keyStore");
            char[] passphrase = System.getProperty("javax.net.ssl.keyStorePassword").toCharArray();
            ks.load(new FileInputStream(fileName), passphrase);
            kmf.init(ks, passphrase);
            sslCtx.init(kmf.getKeyManagers(), trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory socketFactory = sslCtx.getSocketFactory();
            Thread.sleep(new Random().nextInt(5 * NB_CLIENTS));
            // Open connection with server
            SSLSocket socket = (SSLSocket) socketFactory.createSocket(this.url.getHost(), this.url.getPort());
            setSocket(socket);
            connections.incrementAndGet();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     *
     * @param args
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            //System.err.println("Usage: java " + CometServletClientTest.class.getName()
            //        + " URL [n] [max] [delay]");
            System.err.println("Usage: java " + CometServletSSLClientTest.class.getName()
                    + " URL [n] [delay]");
            System.err.println("\tURL: The url of the service to test.");
            System.err.println("\tn: The number of threads. (default is " + NB_CLIENTS + ")");
            // System.err.println("\tmax: The maximum number of requests. (default is 1000)");
            System.err.println("\tdelay: The delay between requests. (default is 1000ms)");
            System.exit(1);
        }

        URL strURL = new URL(args[0]);
        int delay = DEFAULT_DELAY;

        if (args.length > 1) {
            try {
                NB_CLIENTS = Integer.parseInt(args[1]);
                //if (args.length > 2) {
                //    max = Integer.parseInt(args[2]);
                //    if (max < 1) {
                //        throw new IllegalArgumentException("Negative number: max");
                //    }
                //}
                if (args.length > 2) {
                    delay = Integer.parseInt(args[2]);
                    if (delay < 1) {
                        throw new IllegalArgumentException("Negative number: delay");
                    }
                }
            } catch (Exception exp) {
                System.err.println("Error: " + exp.getMessage());
                System.exit(1);
            }
        }

        System.out.println("\nRunning test with parameters:");
        System.out.println("\tURL: " + strURL);
        System.out.println("\tn: " + NB_CLIENTS);
        //System.out.println("\tmax: " + max);
        System.out.println("\tdelay: " + delay);
        
        InputStream in = CometServletSSLClientTest.class.getResourceAsStream("ssl-config.properties");                
        System.getProperties().load(in);
        
        String home = System.getProperty("user.home");
        String trustStoreFileName = System.getProperty("javax.net.ssl.trustStore").replace("~", home);
        System.setProperty("javax.net.ssl.trustStore", trustStoreFileName);
        String keyStoreFileName = System.getProperty("javax.net.ssl.keyStore").replace("~", home);
        System.setProperty("javax.net.ssl.keyStore", keyStoreFileName);

        Thread clients[] = new Thread[NB_CLIENTS];
        for (int i = 0; i < clients.length; i++) {
            clients[i] = new CometServletSSLClientTest(strURL, delay);
        }
        for (int i = 0; i < clients.length; i++) {
            clients[i].start();
        }
        for (int i = 0; i < clients.length; i++) {
            clients[i].join();
        }
    }
}
