package com.synaltic.cxf.cert;

import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.security.transport.TLSSessionInfo;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.*;

public class CertInterceptor extends AbstractPhaseInterceptor<Message> {

    private final static Logger LOG = LoggerFactory.getLogger(CertInterceptor.class);

    public static final String CONFIG_PID = "com.synaltic.cxf.cert";

    private final ConfigurationAdmin configurationAdmin;

    public CertInterceptor(ConfigurationAdmin configurationAdmin) {
        this(Phase.PRE_STREAM, configurationAdmin);
    }

    public CertInterceptor(String phase, ConfigurationAdmin configurationAdmin) {
        super(phase);
        this.configurationAdmin = configurationAdmin;
    }

    public void handleMessage(Message message) throws Fault {
        String busId = message.getExchange().getBus().getId();
        if (!isEnabled(busId)) {
            LOG.debug("Synaltic Cert Interceptor is disabled for CXF Bus {}", busId);
            return;
        }
        LOG.debug("Incoming client message");
        TLSSessionInfo tlsSession = message.get(TLSSessionInfo.class);
        LOG.debug("Get TLS session info");
        if (tlsSession == null) {
            LOG.error("No TLS connection");
            throw new SecurityException("No TLS connection");
        }

        LOG.debug("Get the peer certificates from the TLS session info");
        Certificate[] certificates = null;
        try {
            certificates = tlsSession.getPeerCertificates();
        } catch (Exception e) {
            LOG.error("Can't get client cert", e);
            throw new SecurityException("Can't get client cert", e);
        }
        if (certificates == null || certificates.length == 0) {
            LOG.error("No certificate found");
            throw new SecurityException("No certificate found");
        }

        LOG.debug("Retrieving certificate");
        // due to RFC5246, senders certificates always come first
        Certificate certificate = certificates[0];

        // validate the certificate
        try {
            LOG.debug("Loading keystore for the CXF bus");
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new FileInputStream(new File(getKeyStorePath(busId))), getKeyStorePassword(busId).toCharArray());

            LOG.debug("Validating certificate key chain over the keystore");
            if (!validateKeyChain((X509Certificate) certificate, keyStore)) {
                LOG.error("Certificate is invalid");
                throw new SecurityException("Certificate is invalid");
            }
        } catch (Exception e) {
            LOG.error("Certificate verification failed", e);
            throw new SecurityException("Certificate verification failed", e);
        }
    }

    protected boolean validateKeyChain(X509Certificate certificate, KeyStore keyStore) throws Exception {
        LOG.debug("Validating key chain");
        X509Certificate[] certificates = new X509Certificate[keyStore.size()];
        int i = 0;
        Enumeration<String> alias = keyStore.aliases();
        while (alias.hasMoreElements()) {
            certificates[i++] = (X509Certificate) keyStore.getCertificate(alias.nextElement());
        }
        return validateKeyChain(certificate, certificates);
    }

    protected boolean validateKeyChain(X509Certificate certificate, X509Certificate... trustedCertificates) throws Exception {
        boolean found = false;
        int i = trustedCertificates.length;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        TrustAnchor anchor;
        Set anchors;
        CertPath path;
        List list;
        PKIXParameters params;
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        while (!found && i > 0) {
            anchor = new TrustAnchor(trustedCertificates[--i], null);
            anchors = Collections.singleton(anchor);
            list = Arrays.asList(new Certificate[] { certificate });
            path = cf.generateCertPath(list);
            params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            if (certificate.getIssuerDN().equals(trustedCertificates[i].getSubjectDN())) {
                try {
                    validator.validate(path, params);
                    if (isSelfSigned(trustedCertificates[i])) {
                        // found root CA
                        found = true;
                    } else if (!certificate.equals(trustedCertificates[i])) {
                        found = validateKeyChain(trustedCertificates[i], trustedCertificates);
                    }
                } catch (Exception e) {
                    // validate failed, check next cert in the trust store
                }
            }
        }
        return found;
    }

    protected boolean isSelfSigned(X509Certificate certificate) throws Exception {
        try {
            PublicKey key = certificate.getPublicKey();
            certificate.verify(key);
            LOG.debug("Certificate is self-signed");
            return true;
        } catch (SignatureException signatureException) {
            return  false;
        } catch (InvalidKeyException invalidKeyException) {
            return false;
        }
    }

    protected String getKeyStorePath(String busId) throws Exception {
        LOG.debug("Get the keystore path for CXF Bus {}", busId);
        Configuration configuration = configurationAdmin.getConfiguration(CONFIG_PID);
        if (configuration != null) {
            Enumeration<String> keys = configuration.getProperties().keys();
            while (keys.hasMoreElements()) {
                String property = keys.nextElement();
                if ((busId + ".keystore.path").matches(property)) {
                    LOG.debug("Actual keystore path is {}", configuration.getProperties().get(busId + ".keystore.path"));
                    return (String) configuration.getProperties().get(property);
                }
            }
            LOG.warn("No keystore path found for CXF Bus {}", busId);
        }
        return null;
    }

    protected String getKeyStorePassword(String busId) throws Exception {
        LOG.debug("Get the keystore password for CXF Bus {}", busId);
        Configuration configuration = configurationAdmin.getConfiguration(CONFIG_PID);
        if (configuration != null) {
            Enumeration<String> keys = configuration.getProperties().keys();
            while (keys.hasMoreElements()) {
                String property = keys.nextElement();
                if ((busId + ".keystore.password").matches(property)) {
                    LOG.debug("Found keystore password for CXF Bus {}", busId);
                    return (String) configuration.getProperties().get(property);
                }
            }
            LOG.warn("No keystore password found for CXF Bus {}", busId);
        }
        return null;
    }

    protected boolean isEnabled(String busId) {
        LOG.debug("Get the keystore path for CXF Bus {}", busId);
        try {
            Configuration configuration = configurationAdmin.getConfiguration(CONFIG_PID);
            if (configuration != null) {
                Enumeration<String> keys = configuration.getProperties().keys();
                while (keys.hasMoreElements()) {
                    String property = keys.nextElement();
                    if ((busId + ".enabled").matches(property)) {
                        return Boolean.parseBoolean((String) configuration.getProperties().get(property));
                    }
                }
            }
        } catch (Exception e) {
            LOG.warn("Can't check if the CXF Bus {} is enabled", busId, e);
        }
        return false;
    }

}
