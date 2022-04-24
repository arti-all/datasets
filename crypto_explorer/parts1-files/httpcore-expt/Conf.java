/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */
package org.example;

import org.apache.http.HttpHost;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.impl.nio.reactor.DefaultListeningIOReactor;
import org.apache.http.impl.nio.reactor.IOReactorConfig;
import org.apache.http.nio.reactor.ConnectingIOReactor;
import org.apache.http.nio.reactor.ListeningIOReactor;
import org.apache.http.protocol.*;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.KeyStore;
import java.util.Properties;


final class Conf {
    public static IOReactorConfig ioReactorConfig;
    /**
     * Properties
     target_host=http://localhost:8280/main
     port
     port_http=8080
     port_https=8443
     io_thread_count=4
     timeout_socket=30000
     timeout_connection=30000
     t_conn_pool_max_total=100
     t_conn_pool_default_max_per_route=20
     key_store_location=keyStore.jks
     key_store_password=123456

     *
     */
    public static Properties serverProperties;

    private Conf() {
    }

    private static void loadProperties() {
        serverProperties = new Properties();
        InputStream input = null;
        try {
            input = new FileInputStream("conf/server.properties");
            // load a properties file
            serverProperties.load(input);
            System.out.println("[INFO] Loaded server properties >> ");
            for (String p : serverProperties.stringPropertyNames()) {
                System.out.println("  " + p + " : " + serverProperties.getProperty(p));
            }
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                    System.out.println("[ERROR] server.properties file not found");
                }
            }
        }
    }

    public static HttpHost getTargetHost() throws Exception {
        String uriStr = getTargetHost("http://localhost:8280/");

        // Target host
        URI uri = new URI(uriStr);
        HttpHost targetHost = new HttpHost(
                uri.getHost(),
                uri.getPort() > 0 ? uri.getPort() : 80,
                uri.getScheme() != null ? uri.getScheme() : "http");
        System.out.println("[Info] Target host: " + targetHost);
        return targetHost;
    }

    public static int getPort() {
        int port = getIntProperty("port", 8080);
        return port;
    }

    public static int getHttpPort() {
        int port = getIntProperty("port_http", 8080);
        return port;
    }


    public static int getHttpsPort() {
        int port = getIntProperty("port_https", 8443);
        return port;
    }

    public static InetSocketAddress newInetSocketAddress(int port) {
        return new InetSocketAddress(port);
    }

    private static int getIntProperty(String name, int defaultValue) {
        if (name == null) {
            return -1;
        }
        if (serverProperties == null) {
            loadProperties();
        }
        int v = defaultValue > 0 ? defaultValue : 4;
        try {
            v = Integer.parseInt(serverProperties.getProperty(name));
        } catch (NumberFormatException e) {

        }
        return v;
    }

    private static String getStringProperty(String name, String defaultValue) {
        if (name == null) {
            return "";
        }
        if (serverProperties == null) {
            loadProperties();
        }
        String v = serverProperties.getProperty(name);
        return v == null ? defaultValue : v;
    }

    public static int getTargetConnectionPoolMaxTotal(int defaultValue) {
        return getIntProperty("t_conn_pool_max_total", defaultValue);
    }

    public static int getTargetConnectionDefaultMaxPerRoute(int defaultValue) {
        return getIntProperty("t_conn_pool_default_max_per_route", defaultValue);
    }

    public static String getTargetHost(String defaulHost) {
        return getStringProperty("target_host", defaulHost);
    }

    public static int getIoThreadCount(int defaultValue) {
        return getIntProperty("io_thread_count", defaultValue);
    }

    public static int getSocketTimeout(int defaultValue) {
        return getIntProperty("timeout_socket", defaultValue);
    }

    public static int getConnectionTimeout(int defaultValue) {
        return getIntProperty("timeout_connection", defaultValue);
    }

    public static void buildIoReactorConfig() {
        ioReactorConfig = IOReactorConfig.custom()
                .setIoThreadCount(getIoThreadCount(4))
                .setSoTimeout(getSocketTimeout(30000))
                .setConnectTimeout(getConnectionTimeout(30000))
                .build();
    }

    public static void showLogMsg(String msg, String clazz) {
        System.out.println("[INFO] [" + Thread.currentThread().getId()
                + "] " + clazz + " # " + msg);
    }

    public static ConnectingIOReactor getConnectingIOReactor() throws Exception {
        if (ioReactorConfig == null) {
            buildIoReactorConfig();
        }
        return new DefaultConnectingIOReactor(ioReactorConfig);
    }

    public static ListeningIOReactor getListeningIOReactor() throws Exception {
        if (ioReactorConfig == null) {
            buildIoReactorConfig();
        }
        return new DefaultListeningIOReactor(ioReactorConfig);
    }

    public static HttpProcessor getIncomingProcessor() {
        return new ImmutableHttpProcessor(
                new ResponseDate(),
                new ResponseServer("Rev-Proxy/1.1"),
                new ResponseContent(),
                new ResponseConnControl());
    }

    public static HttpProcessor getOutgoingProcessor() {
        return new ImmutableHttpProcessor(
                new RequestContent(),
                new RequestTargetHost(),
                new RequestConnControl(),
                new RequestUserAgent("Rev-Proxy/1.1"),
                new RequestExpectContinue(true));
    }

    public static SSLContext getSslContext() {
        char[] secret = getStringProperty("key_store_password", "changeit").toCharArray();
        try {
            URL url = new URL("file://" + getStringProperty("key_store_location", ""));
            KeyStore keystore = KeyStore.getInstance("jks");
            keystore.load(url.openStream(), secret);
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keystore, secret);
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
            SSLContext sslcontext = SSLContext.getInstance("TLS");
            sslcontext.init(keyManagers, null, null);
            return sslcontext;
        } catch (Exception e) {
            System.out.println("[ERROR] Could not create SSL Context: " + e.getLocalizedMessage());
            return null;
        }
    }

}
