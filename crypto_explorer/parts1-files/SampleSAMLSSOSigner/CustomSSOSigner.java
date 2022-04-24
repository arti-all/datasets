/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein is strictly forbidden, unless permitted by WSO2 in accordance with
 * the WSO2 Commercial License available at http://wso2.com/licenses. For specific
 * language governing the permissions and limitations under this license,
 * please see the license as well as any agreement you’ve entered into with
 * WSO2 governing the purchase of this software and any associated services.
 */

package org.wso2.custom.sso.signer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.c14n.Canonicalizer;
import org.opensaml.saml2.core.impl.ResponseImpl;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.*;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.builders.signature.DefaultSSOSigner;

import javax.xml.namespace.QName;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

public class CustomSSOSigner extends DefaultSSOSigner {

    private static Log log = LogFactory.getLog(CustomSSOSigner.class);

    @Override
    public void init() throws IdentityException {

    }

    @Override
    public SignableXMLObject setSignature(SignableXMLObject signableXMLObject, String signatureAlgorithm,
                                          String digestAlgorithm, X509Credential cred) throws IdentityException {
        try {
            String issuer = selectIssuerByType(signableXMLObject);
            cred = getRequiredCredentials(issuer);
            Signature signature = (Signature) buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
            signature.setSigningCredential(cred);
            signature.setSignatureAlgorithm(signatureAlgorithm);
            signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            try {
                KeyInfo keyInfo = (KeyInfo) buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
                X509Data data = (X509Data) buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
                X509Certificate cert = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);

                String value = org.apache.xml.security.utils.Base64.encode(cred
                        .getEntityCertificate().getEncoded());
                cert.setValue(value);
                data.getX509Certificates().add(cert);
                keyInfo.getX509Datas().add(data);
                signature.setKeyInfo(keyInfo);
            } catch (CertificateEncodingException e) {
                throw IdentityException.error("Error occurred while retrieving encoded cert", e);
            }

            signableXMLObject.setSignature(signature);

            List<Signature> signatureList = new ArrayList<Signature>();
            signatureList.add(signature);

            // Marshall and Sign
            MarshallerFactory marshallerFactory = org.opensaml.xml.Configuration
                    .getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(signableXMLObject);

            marshaller.marshall(signableXMLObject);

            org.apache.xml.security.Init.init();
            Signer.signObjects(signatureList);
            return signableXMLObject;
        } catch (Exception e) {
            throw IdentityException.error("Error occurred while retrieving encoded cert", e);
        }
    }

    /**
     * Builds SAML Elements
     *
     * @param objectQName
     * @return
     * @throws IdentityException
     */
    private XMLObject buildXMLObject(QName objectQName) throws IdentityException {
        XMLObjectBuilder builder =
                org.opensaml.xml.Configuration.getBuilderFactory()
                        .getBuilder(objectQName);
        if (builder == null) {
            throw IdentityException.error("Error occurred while retrieving encoded cert");
        }
        return builder.buildObject(objectQName.getNamespaceURI(), objectQName.getLocalPart(),
                objectQName.getPrefix());
    }

    /**
     * Customizations to get desired credentials
     * cd ../
     *
     * @return
     */
    private X509Credential getRequiredCredentials(String issuer) {

        KeyStore keyStore = null;
        FileInputStream fis = null;
        KeyStoreInfo keyStoreInfo = selectKeyStorebyPreference(issuer);
        String keyStorePath = keyStoreInfo.getKeyStorePath();
        String keyPassword = keyStoreInfo.getKeyStorePassword();
        String keyAlias = keyStoreInfo.getKeyStoreAlias();
        char[] passwordc = keyPassword.toCharArray();

        log.info("Starting getting credentials from key store: " + keyStorePath);
        // Get Default Instance of KeyStore
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            log.error("Error while Intializing Keystore", e);
        }

        // Read KeyStore as file Input Stream
        try {
            fis = new FileInputStream(keyStorePath);
        } catch (FileNotFoundException e) {
            log.error("Unable to found KeyStore with the given keystoere name ::" + keyStorePath, e);
        }

        // Load KeyStore
        try {
            keyStore.load(fis, passwordc);
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to Load the KeyStore:: ", e);
        } catch (CertificateException e) {
            log.error("Failed to Load the KeyStore:: ", e);
        } catch (IOException e) {
            log.error("Failed to Load the KeyStore:: ", e);
        }

        // Close InputFileStream
        try {
            fis.close();
        } catch (IOException e) {
            log.error("Failed to close file stream:: ", e);
        }

        // Get Private Key Entry From Certificate
        KeyStore.PrivateKeyEntry pkEntry = null;
        try {
            pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyAlias, new KeyStore.PasswordProtection(passwordc));
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to Get Private Entry From the keystore:: " + keyStorePath, e);
        } catch (UnrecoverableEntryException e) {
            log.error("Failed to Get Private Entry From the keystore:: " + keyStorePath, e);
        } catch (KeyStoreException e) {
            log.error("Failed to Get Private Entry From the keystore:: " + keyStorePath, e);
        }

        Map<String, String> passwordMap = new HashMap<String, String>();
        passwordMap.put(keyAlias, keyPassword);
        KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keyStore, passwordMap);

        Criteria criteria = new EntityIDCriteria(keyAlias);
        CriteriaSet criteriaSet = new CriteriaSet(criteria);

        X509Credential credential = null;
        try {
            credential = (X509Credential) resolver.resolveSingle(criteriaSet);
        } catch (org.opensaml.xml.security.SecurityException e) {
            log.error("Failed to create credentials..");
        }

        log.info("Finished loading credentials from key store. Proceeding to sign");

        return credential;
    }

    /**
     * Method that returns the Keystore information.
     * @param issuer
     * @return Keystore information
     * your logic selecting keystore by passing issuer name goes here.
     */

    private KeyStoreInfo selectKeyStorebyPreference(String issuer) {
        KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setKeyStorePath("/home/siluni/issues/ELCOHUBPROD-399/wso2is-5.1.0/repository/resources/security" +
                "/wso2carbonold.jks");
        keyStoreInfo.setKeyStoreAlias("wso2carbonold");
        keyStoreInfo.setKeyStorePassword("wso2carbonold");

        return keyStoreInfo;
    }
    /**
     * Method that returns issuer by casting according to the type.
     * @param signableXMLObject
     * @return issuer name
     * your logic selecting keystore by passing client ID goes here.
     */

    private String selectIssuerByType(SignableXMLObject signableXMLObject) {
        String issuer = "";

        if (signableXMLObject.getClass().toString().equals("org.opensaml.saml2.core.impl.ResponseImpl")) {
            issuer = ((ResponseImpl) signableXMLObject).getIssuer().toString();
        } else if (signableXMLObject.getClass().toString().equals("oorg.opensaml.saml2.core.impl.AssertionImpl")) {
            issuer = ((org.opensaml.saml2.core.impl.AssertionImpl) signableXMLObject).getIssuer().toString();
        } else {
        }
        return issuer;

    }
}
