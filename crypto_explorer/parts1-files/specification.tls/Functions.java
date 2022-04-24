/*
 * Copyright 2014, Kaazing Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kaazing.specification.tls;

import org.kaazing.k3po.lang.el.Function;
import org.kaazing.k3po.lang.el.spi.FunctionMapperSpi;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class Functions {

    private Functions() {
        // utility
    }

    @Function
    public static byte[] testHello() {
        return "helloworld".getBytes();
    }

    @Function
    public static byte[] clientHello() throws IOException {
        // ClientHello
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ClientHello clientHello = new ClientHello();
        clientHello.write(os);
        byte[] body = os.toByteArray();

        // Handshake
        os = new ByteArrayOutputStream();
        Handshake handshake = new Handshake(HandshakeType.CLIENT_HELLO, body);
        handshake.write(os);
        byte[] fragment = os.toByteArray();

        // TlsPlainText
        os = new ByteArrayOutputStream();
        TlsPlaintext tlsPlaintext = new TlsPlaintext(ContentType.HANDSHAKE, fragment, fragment.length);
        tlsPlaintext.write(os);
        byte[] hello = os.toByteArray();

        return hello;
    }

    @Function
    public static byte[] serverHello() throws IOException {

        // ServerHello body
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        ServerHello serverHello = new ServerHello(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        serverHello.write(os);
        byte[] helloBody = os.toByteArray();

        // Certificate body
        os = new ByteArrayOutputStream();
        Certificate certificate = new Certificate("localhost");
        certificate.write(os);
        byte[] certBody = os.toByteArray();

        // ServerHelloDone body
        os = new ByteArrayOutputStream();
        ServerHelloDone done = new ServerHelloDone();
        done.write(os);
        byte[] doneBody = os.toByteArray();

        // Handshake
        // ServerHello
        os = new ByteArrayOutputStream();
        Handshake handshake = new Handshake(HandshakeType.SERVER_HELLO, helloBody);
        handshake.write(os);
        // Certificate
        handshake = new Handshake(HandshakeType.CERTIFICATE, certBody);
        handshake.write(os);
        // Server Hello Done
        handshake = new Handshake(HandshakeType.SERVER_HELLO_DONE, doneBody);
        handshake.write(os);
        byte[] fragment = os.toByteArray();

        // TlsPlainText
        os = new ByteArrayOutputStream();
        TlsPlaintext tlsPlaintext = new TlsPlaintext(ContentType.HANDSHAKE, fragment, fragment.length);
        tlsPlaintext.write(os);
        byte[] hello = os.toByteArray();

        return hello;
    }

    public static class Mapper extends FunctionMapperSpi.Reflective {

        public Mapper() {
            super(Functions.class);
        }

        @Override
        public String getPrefixName() {
            return "tls";
        }

    }

    interface Encoder {
        void write(OutputStream os) throws IOException;
    }

    interface Decoder {
        void read(InputStream is) throws IOException;
    }

    static class Random implements Encoder, Decoder {

        @Override
        public void read(InputStream is) throws IOException {
            readFully(is, new byte[32]);
        }

        @Override
        public void write(OutputStream os) throws IOException {
            byte[] randomBytes = new byte[32];

            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(randomBytes);

            int gmtUnixTime = (int) (System.currentTimeMillis() / 1000);
            randomBytes[0] = (byte) (gmtUnixTime >> 24);
            randomBytes[1] = (byte) (gmtUnixTime >> 16);
            randomBytes[2] = (byte) (gmtUnixTime >> 8);
            randomBytes[3] = (byte) gmtUnixTime;

            os.write(randomBytes);
        }
    }


    static class Extension implements Encoder, Decoder {


        @Override
        public void read(InputStream is) throws IOException {

        }

        @Override
        public void write(OutputStream os) throws IOException {

        }
    }

    static enum CompressionMethod implements Encoder, Decoder {
        NULL((byte) 0x00);

        private final byte b1;

        CompressionMethod(byte b1) {
            this.b1 = b1;
        }

        @Override
        public void read(InputStream is) throws IOException {
            readFully(is, new byte[1]);
        }

        @Override
        public void write(OutputStream os) throws IOException {
            os.write(b1);
        }
    }

    static class SessionId implements Encoder, Decoder {

        final byte[] id;

        SessionId() {
            this(false);
        }

        SessionId(boolean generate) {
            id = generate ? new byte[32] : new byte[0];
            if (generate) {
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(id);
            }
        }

        @Override
        public void read(InputStream is) throws IOException {
            int len = is.read();
            if (len == 0 || len == 32) {
                readFully(is, new byte[len]);
                return;
            }
            throw new IOException();
        }

        @Override
        public void write(OutputStream os) throws IOException {
            os.write(id.length);
            os.write(id);
        }
    }

    static class ServerHello implements Encoder, Decoder {
        byte[] serverVersion = new byte[] {0x03, 0x03};
        Random random = new Random();
        SessionId sessionId = new SessionId(true);
        CipherSuite cipherSuite;
        CompressionMethod compressionMethod = CompressionMethod.NULL;

        List<Extension> extensionList = new ArrayList<>();

        ServerHello(CipherSuite cipherSuite) {
            this.cipherSuite = cipherSuite;
        }

        @Override
        public void read(InputStream is) throws IOException {

        }

        @Override
        public void write(OutputStream os) throws IOException {
            os.write(serverVersion);
            random.write(os);
            sessionId.write(os);
            cipherSuite.write(os);
            compressionMethod.write(os);

            os.write((extensionList.size() >> 8) & 0xff);
            os.write(extensionList.size() & 0xff);
            for (Extension extension : extensionList) {
                extension.write(os);
            }

        }
    }

    static class Certificate implements Encoder, Decoder {
        java.security.cert.Certificate[] certs;

        Certificate(String alias) {
            char[] password = "ab987c".toCharArray();
            try {
                KeyStore keyStore = KeyStore.getInstance("JCEKS");
                InputStream cis = getClass().getClassLoader().getResourceAsStream("keystore.db");
                keyStore.load(cis, password);
                cis.close();

                certs = keyStore.getCertificateChain(alias);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void read(InputStream is) throws IOException {

        }

        @Override
        public void write(OutputStream os) throws IOException {
            List<byte[]> encoded = new ArrayList<>();
            int total = 0;
            for (java.security.cert.Certificate cert : certs) {
                byte[] certEncodedData;
                try {
                    certEncodedData = cert.getEncoded();
                } catch (CertificateEncodingException ce) {
                    throw new IOException(ce);
                }
                total += 3;
                total += certEncodedData.length;
                encoded.add(certEncodedData);
            }
            os.write((total >> 16) & 0xff);
            os.write((total >> 8) & 0xff);
            os.write(total & 0xff);
            for (byte[] data : encoded) {
                int len = data.length;
                os.write((len >> 16) & 0xff);
                os.write((len >> 8) & 0xff);
                os.write(len & 0xff);
                os.write(data);
            }
        }
    }


    static class ClientHello implements Encoder, Decoder {
        byte[] clientVersion = new byte[] {0x03, 0x03};
        Random random = new Random();
        SessionId sessionId = new SessionId();
        List<CipherSuite> cipherSuiteList = new ArrayList<>();
        List<CompressionMethod> compressionMethodList = new ArrayList<>();

        List<Extension> extensionList = new ArrayList<>();

        ClientHello() {
            compressionMethodList.add(CompressionMethod.NULL);
            Collections.addAll(cipherSuiteList, CipherSuite.values());
        }

        @Override
        public void read(InputStream is) throws IOException {
            readFully(is, new byte[2]);
            random.read(is);
            sessionId.read(is);

            byte[] cipherSuiteLength = new byte[2];
            readFully(is, cipherSuiteLength);
            int len = (cipherSuiteLength[0] << 8) | cipherSuiteLength[1];
            readFully(is, new byte[len]);

            byte[] compressionMethodLength = new byte[1];
            readFully(is, compressionMethodLength);
            len =  compressionMethodLength[1];
            readFully(is, new byte[len]);

            byte[] extensionsLength = new byte[2];
            readFully(is, extensionsLength);
            len = (extensionsLength[0] << 8) | extensionsLength[1];
            readFully(is, new byte[len]);
        }

        @Override
        public void write(OutputStream os) throws IOException {
            os.write(clientVersion);
            random.write(os);
            sessionId.write(os);

            assert cipherSuiteList.size() > 1;
            int cipherSuiteLength = cipherSuiteList.size() * 2;
            os.write((cipherSuiteLength >> 8) & 0xff);
            os.write(cipherSuiteLength & 0xff);
            for (CipherSuite cipherSuite : cipherSuiteList) {
                cipherSuite.write(os);
            }

            assert compressionMethodList.size() > 0;
            os.write(compressionMethodList.size());
            for (CompressionMethod compressionMethod : compressionMethodList) {
                compressionMethod.write(os);
            }

            os.write((extensionList.size() >> 8) & 0xff);
            os.write(extensionList.size() & 0xff);
            for (Extension extension : extensionList) {
                extension.write(os);
            }

        }
    }

    static class ServerHelloDone implements Encoder, Decoder {

        @Override
        public void read(InputStream is) throws IOException {
        }

        @Override
        public void write(OutputStream os) throws IOException {
        }
    }



    enum CipherSuite implements Encoder, Decoder {
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xc009),
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013),
        TLS_RSA_WITH_AES_128_CBC_SHA (0x002f),
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xc004),
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xc00e),
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033),
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032),
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007),
        TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011),
        TLS_RSA_WITH_RC4_128_SHA (0x0005),
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA (0xc002),
        TLS_ECDH_RSA_WITH_RC4_128_SHA (0xc00c),
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008),
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012),
        TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a),
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc003),
        TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xc00d),
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016),
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (0x0013),
        TLS_RSA_WITH_RC4_128_MD5 (0x0004),
        TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff);

        private final int b1;

        private CipherSuite(int b1) {
            this.b1 = b1;
        }

        @Override
        public void read(InputStream is) throws IOException {
            readFully(is, new byte[2]);
        }

        @Override
        public void write(OutputStream os) throws IOException {
            os.write((b1 >> 8) & 0xff);
            os.write(b1 & 0xff);
        }
    }

    enum ContentType implements Encoder, Decoder {
        CHANGE_CIPHER_SPEC(20),
        ALERT(21),
        HANDSHAKE(22),
        APPLICATION_DATA(23);

        private final int b;

        private ContentType(int b) {
            this.b = b;
        }

        @Override
        public void read(InputStream is) throws IOException {
            readFully(is, new byte[1]);
        }

        @Override
        public void write(OutputStream os) throws IOException {
            os.write(b);
        }
    }

    static class TlsPlaintext implements Encoder, Decoder {
        final ContentType contentType;
        final byte[] version = new byte[] { 0x03, 0x03 };     // TLS v1.2
        final int length;
        final byte[] fragment;

        TlsPlaintext(ContentType contentType, byte[] fragment, int length) {
            this.contentType = contentType;
            this.fragment = fragment;
            this.length = length;
        }

        @Override
        public void read(InputStream is) throws IOException {
            contentType.read(is);
            readFully(is, new byte[2]);
            byte[] length = new byte[2];
            readFully(is, length);
            int len = (length[0] << 8) | length[1];
            readFully(is, new byte[len]);
        }

        @Override
        public void write(OutputStream os) throws IOException {
            contentType.write(os);
            os.write(version);
            os.write((length >> 8) & 0xff);
            os.write(length & 0xff);
            os.write(fragment);
        }
    }

    enum HandshakeType implements Encoder, Decoder {
        HELLO_REQUEST(0),
        CLIENT_HELLO(1),
        SERVER_HELLO(2),
        CERTIFICATE(11),
        SERVER_KEY_EXCHANGE (12),
        CERTIFICATE_REQUEST(13),
        SERVER_HELLO_DONE(14),
        CERTIFICATE_VERIFY(15),
        CLIENT_KEY_EXCHANGE(16),
        FINISHED(20);

        private final int b;

        private HandshakeType(int b) {
            this.b = b;
        }

        @Override
        public void read(InputStream is) throws IOException {

        }

        @Override
        public void write(OutputStream os) throws IOException {
            os.write(b);
        }

    }

    static class Handshake implements Encoder, Decoder {
        final HandshakeType msgType;
        final byte[] body;

        Handshake(HandshakeType msgType, byte[] body) {
            this.msgType = msgType;
            this.body = body;
        }

        @Override
        public void read(InputStream is) throws IOException {

        }

        @Override
        public void write(OutputStream os) throws IOException {
            msgType.write(os);
            os.write((body.length >> 16) & 0xff);
            os.write((body.length >> 8) & 0xff);
            os.write(body.length & 0xff);
            os.write(body);
        }
    }

    static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b: a) {
            sb.append(String.format("%02x ", b & 0xff));
        }
        return sb.toString();
    }

    static void readFully(InputStream is, byte[] data) throws IOException {
        int n = 0, len = data.length, off = 0;
        while (n < len) {
            int count = is.read(data, off + n, len - n);
            if (count < 0) {
                throw new EOFException();
            }
            n += count;
        }
    }

}

