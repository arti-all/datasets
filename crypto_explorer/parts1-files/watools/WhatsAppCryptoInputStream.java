/*
 * Copyright 2016 Fritz Elfert
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.felfert.watools;

import java.io.File;
import java.io.FileInputStream;
import java.io.FilterInputStream;
import java.io.InputStream;
import java.io.IOException;

import java.util.Arrays;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import java.security.MessageDigest;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;

import javax.annotation.Nonnull;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A FilterInputStream implementation for reading encrypted WhatsApp databases.
 */
public class WhatsAppCryptoInputStream extends FilterInputStream {

    private static final Logger LOGGER = LoggerFactory.getLogger(WhatsAppCryptoInputStream.class);

    private static final String CRYPTO_PROVIDER_PROPKEY = "com.github.felfert.watools.CryptoProvider";
    private static final String CRYPTO_PROVIDER_DEFAULT = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    private static final String CRYPTO_PROVIDER = System.getProperty(CRYPTO_PROVIDER_PROPKEY, CRYPTO_PROVIDER_DEFAULT);

    /**
     * Creates a new instance from a database file and a key file.
     *
     * @param infile The encrypted database file.
     * <p>The {@link WhatsAppCryptoVersion} is chosen according to the extension of the file name.</p>
     * @param keyfile The corresponding key file.
     * @throws IOException if initialization fails.
     */
    public WhatsAppCryptoInputStream(@Nonnull final File infile, @Nonnull final File keyfile) throws IOException {
        this(new FileInputStream(infile), WhatsAppCryptoVersion.fromFile(infile), getKeyMaterialFromFile(keyfile));
    }

    /**
     * Creates a new instance from a database file and a key file.
     * @param infile The encrypted database file.
     * @param v The version of encryption.
     * @param keyfile The corresponding key file.
     * @throws IOException if initialization fails.
     */
    public WhatsAppCryptoInputStream(@Nonnull final File infile, WhatsAppCryptoVersion v,
            @Nonnull final File keyfile) throws IOException {
        this(new FileInputStream(infile), v, getKeyMaterialFromFile(keyfile));
    }

    /**
     * Creates a new instance from a database file and an account name.
     * @param infile The encrypted database file.
     * @param account The account name to use.
     * @throws IOException if initialization fails.
     */
    public WhatsAppCryptoInputStream(@Nonnull final File infile, @Nonnull final String account) throws IOException {
        this(new FileInputStream(infile), WhatsAppCryptoVersion.CRYPT5, account.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Creates a new instance from an input stream and an account name.
     * @param indata The underlying encrypted input stream.
     * @param account The account name to use.
     * @throws IOException if initialization fails.
     */
    public WhatsAppCryptoInputStream(@Nonnull final InputStream indata, @Nonnull final String account)
            throws IOException {
        this(indata, WhatsAppCryptoVersion.CRYPT5, account.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Creates a new instance from a database file and keyMaterial.
     * @param indata The underlying encrypted input stream.
     * @param v The version of encryption.
     * @param keyMaterial The key material to use.
     * <p>In case of {@link WhatsAppCryptoVersion#CRYPT5}, this is the account name. Otherwise it is
     * the content of the key file which should always be 158 bytes.</p>
     * @throws IOException if initialization fails.
     */
    public WhatsAppCryptoInputStream(@Nonnull final InputStream indata, WhatsAppCryptoVersion v,
            @Nonnull final byte[] keyMaterial) throws IOException {
        super(setup(indata, v, keyMaterial));
    }

    private static final byte[] BASE5KEY =
        DatatypeConverter.parseHexBinary("8d4b155cc9ff81e5cbf6fa7819366a3ec621a656416cd793");
    private static final byte[] BASE5IV = DatatypeConverter.parseHexBinary("1e39f369e90db33aa73b442bbbb6b0b9");
    private static final String AESCBC = "AES/CBC/PKCS5Padding";
    private static final String AESGCM = "AES/GCM/NoPadding";

    private static InputStream setup(@Nonnull final InputStream indata, WhatsAppCryptoVersion v,
            @Nonnull final byte[] keyMaterial) throws IOException {
        byte[] key;
        byte[] iv;
        switch (v) {
            case CRYPT5:
                final byte[] accountMD5 = getMD5().digest(keyMaterial);
                key = new byte[BASE5KEY.length];
                for (int i = 0; i < BASE5KEY.length; i++) {
                    key[i] = (byte)(BASE5KEY[i] ^ accountMD5[i & 15]);
                }
                iv = Arrays.copyOf(BASE5IV, BASE5IV.length);
                return new CipherInputStream(indata, createCipher(AESCBC, key, iv));
            case CRYPT7:
                checkKeyMaterial(keyMaterial, 158);
                iv = Arrays.copyOfRange(keyMaterial, 110, 126);
                key = Arrays.copyOfRange(keyMaterial, 126, 158);
                return new CipherInputStream(indata, createCipher(AESCBC, key, iv));
            case CRYPT8:
                checkKeyMaterial(keyMaterial, 158);
                key = Arrays.copyOfRange(keyMaterial, 126, 158);
                iv = getIvFromInput(indata, keyMaterial);
                return new InflaterInputStream(new CipherInputStream(indata,
                            createCipher(AESCBC, key, iv)), new Inflater(false));
            case CRYPT12:
                checkKeyMaterial(keyMaterial, 158);
                key = Arrays.copyOfRange(keyMaterial, 126, 158);
                iv = getIvFromInput(indata, keyMaterial);
                return new InflaterInputStream(new CipherInputStream(indata,
                            createCipher(AESGCM, key, iv)), new Inflater(false));
            default:
                throw new IllegalArgumentException("Unsupported crypto version");
        }
    }

    @Nonnull
    private static Cipher createCipher(@Nonnull final String spec, @Nonnull final byte[] key,
            @Nonnull final byte[] iv) throws IOException {
        LOGGER.debug("Using cipher {} with key of {} bytes and IV of {} bytes", spec, key.length, iv.length);
        try {
            insertCustomProvider();
            Cipher cipher = Cipher.getInstance(spec);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher;
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                InvalidAlgorithmParameterException | NoSuchPaddingException x) {
            throw new IOException("Could not initialize decryption", x);
        }
    }

    private static void insertCustomProvider() throws IOException {
        for (Provider p : Security.getProviders()) {
            if (p.getClass().getName().equals(CRYPTO_PROVIDER)) {
                return;
            }
        }
        try {
            Object o = Class.forName(CRYPTO_PROVIDER).newInstance();
            if (o instanceof Provider) {
                int pos = Security.insertProviderAt((Provider)o, 1); 
                if (1 != pos) {
                    LOGGER.warn("{} was inserted at position {}", pos);
                }
            } else {
                throw new IOException(CRYPTO_PROVIDER + " is not an instance of "  + Provider.class.getName());
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException x) {
            throw new IOException("Could not insert crypto provider class " + CRYPTO_PROVIDER, x);
        }
    }

    @Nonnull
    private static byte[] getIvFromInput(@Nonnull final InputStream is, @Nonnull byte[] keyMaterial)
            throws IOException {
        int idx = 0;
        int remaining = 67;
        byte[] buf = new byte[remaining];
        while (remaining > 0) {
            int r = is.read(buf, idx, remaining);
            if (r < 0) {
                throw new IOException("Premature EOF while reading header");
            }
            remaining -= r;
            idx += r;
        }
        byte[] cmpA = Arrays.copyOfRange(keyMaterial, 30, 62);
        byte[] cmpB = Arrays.copyOfRange(buf, 3, 35);
        if (!Arrays.equals(cmpA, cmpB)) {
            throw new IOException("Keyfile/Datafile mismatch");
        }
        return Arrays.copyOfRange(buf, 51, 67);
    }

    @Nonnull
    private static byte[] getKeyMaterialFromFile(@Nonnull final File keyfile) throws IOException {
        if (!keyfile.canRead()) {
            throw new IOException("Key file can not be read");
        }
        if (keyfile.length() > 1024) {
            throw new IOException("Key file size exceeds 1024 bytes");
        }
        return Files.readAllBytes(keyfile.toPath());
    }

    private static void checkKeyMaterial(@Nonnull final byte[] keyMaterial, final int expectedSize) throws IOException {
        if (keyMaterial.length != expectedSize) {
            throw new IOException(String.format("Key material size is not %d", expectedSize));
        }
    }

    @Nonnull
    private static MessageDigest getMD5() {
        try {
            return MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException x) {
            // Per SPEC, Java >= 6 comes with builtin MD5
            throw new IllegalStateException("Should never happen", x);
        }
    }
}
