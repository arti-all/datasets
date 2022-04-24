/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.servicemix.soap.handlers.security;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.CredentialException;
import org.apache.ws.security.components.crypto.CryptoType;
import org.springframework.core.io.Resource;

public class StandaloneCrypto extends BaseCrypto {

    private Resource keyStoreUrl;
    private String keyStoreType;
    private String keyStorePassword;
    private KeyStore keyStore;
    private String keyPassword;
    
    /**
     * @return the keyPassword
     */
    public String getKeyPassword() {
        return keyPassword;
    }

    /**
     * @param keyPassword the keyPassword to set
     */
    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    /**
     * @return the keyStorePassword
     */
    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    /**
     * @param keyStorePassword the keyStorePassword to set
     */
    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    /**
     * @return the keyStoreType
     */
    public String getKeyStoreType() {
        return keyStoreType;
    }

    /**
     * @param keyStoreType the keyStoreType to set
     */
    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    /**
     * @return the keyStoreUrl
     */
    public Resource getKeyStoreUrl() {
        return keyStoreUrl;
    }

    /**
     * @param keyStoreUrl the keyStoreUrl to set
     */
    public void setKeyStoreUrl(Resource keyStoreUrl) {
        this.keyStoreUrl = keyStoreUrl;
    }

    protected String[] getAliases() throws KeyStoreException {
        List aliases = Collections.list(loadKeyStore().aliases());
        return (String[]) aliases.toArray(new String[aliases.size()]);
    }

    protected Certificate getCertificate(String alias) throws KeyStoreException {
        return loadKeyStore().getCertificate(alias);
    }

    protected String getCertificateAlias(Certificate cert) throws KeyStoreException {
        return loadKeyStore().getCertificateAlias(cert);
    }

    protected Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return loadKeyStore().getCertificateChain(alias);
    }

    public PrivateKey getPrivateKey(String alias, String password) throws WSSecurityException {
        // The password given here is a dummy password
        // See WSSecurityHandler.DefaultHandler#processSignature
        password = keyPassword;
        if (password == null) {
            password = keyStorePassword;
        }
        if (alias == null) {
            throw new WSSecurityException("alias is null");
        }
        KeyStore keystore = null;
        try {
            keystore = loadKeyStore();
        } catch (Exception e) {
            throw new WSSecurityException("Cannot load key store", e);
        }
        boolean b = false;
        try {
            b = keystore.isKeyEntry(alias);
        } catch (KeyStoreException e) {
            throw new WSSecurityException("Cannot find key for alias: " + alias, e);
        }
        if (!b) {
            throw new WSSecurityException("Cannot find key for alias: " + alias);
        }
        Key keyTmp = null;
        try {
            keyTmp = keystore.getKey(alias, (password == null || password.length() == 0) ? new char[0] : password.toCharArray());
        } catch (Exception e) {
            throw new WSSecurityException("Cannot get private key", e);
        }       
        if (!(keyTmp instanceof PrivateKey)) {
            throw new WSSecurityException("Key is not a private key, alias: " + alias);
        }
        return (PrivateKey) keyTmp;
    }

    protected String[] getTrustCertificates() throws KeyStoreException {
        KeyStore keystore = loadKeyStore();
        Set hashSet = new HashSet();
        Enumeration aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = (String) aliases.nextElement();
            if (keystore.isCertificateEntry(alias)) {
                hashSet.add(alias);
            }
        }
        return (String[]) hashSet.toArray(new String[hashSet.size()]);
    }
    
    /**
     * Loads the the keystore.
     *
     * @throws CredentialException
     */
    public synchronized KeyStore loadKeyStore() throws KeyStoreException {
        if (keyStore != null) {
            return keyStore;
        }
        if (keyStoreUrl == null) {
            throw new IllegalArgumentException("keyStoreUrl not specified in this StandaloneCrypto");
        }
        InputStream input = null;
        try {
            input = keyStoreUrl.getInputStream();
            String provider = getProvider();
            String type = keyStoreType != null ? keyStoreType : KeyStore.getDefaultType();
            if (provider == null || provider.length() == 0) {
                keyStore = KeyStore.getInstance(type);
            } else {
                keyStore = KeyStore.getInstance(type, provider);
            }
            keyStore.load(input, (keyStorePassword == null || keyStorePassword.length() == 0) ? new char[0] : keyStorePassword.toCharArray());
            return keyStore;
        } catch (IOException e) {
            throw new KeyStoreException(e);
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException(e);
        } catch (Exception e) {
            throw new KeyStoreException(e);
        } finally {
            if (input != null) {
                try { input.close(); } catch (Exception ignore) {} 
            }
        }
    }

    public String getCryptoProvider() {
        // TODO Auto-generated method stub
        return null;
    }

    public void setCryptoProvider(String provider) {
        // TODO Auto-generated method stub
        
    }

    public String getDefaultX509Identifier() throws WSSecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public void setDefaultX509Identifier(String identifier) {
        // TODO Auto-generated method stub
        
    }

    public void setCertificateFactory(String provider, CertificateFactory certFactory) {
        // TODO Auto-generated method stub
        
    }

    public byte[] getBytesFromCertificates(X509Certificate[] certs) throws WSSecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public X509Certificate[] getCertificatesFromBytes(byte[] data) throws WSSecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public String getX509Identifier(X509Certificate cert) throws WSSecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public PrivateKey getPrivateKey(X509Certificate certificate, CallbackHandler callbackHandler)
        throws WSSecurityException {
        // TODO Auto-generated method stub
        return null;
    }

    public boolean verifyTrust(X509Certificate[] certs) throws WSSecurityException {
        // TODO Auto-generated method stub
        return false;
    }

    public boolean verifyTrust(PublicKey publicKey) throws WSSecurityException {
        // TODO Auto-generated method stub
        return false;
    }

    public boolean verifyTrust(X509Certificate[] certs, boolean enableRevocation) throws WSSecurityException {
        return false;
    }

}
