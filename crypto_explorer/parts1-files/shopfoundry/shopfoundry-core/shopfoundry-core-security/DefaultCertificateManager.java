package org.shopfoundry.core.security.certificates;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.openssl.PEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Bojan Bijelic
 */
public class DefaultCertificateManager implements CertificateManager {

	private static final Logger logger = LoggerFactory.getLogger(DefaultCertificateManager.class);

	private KeyStore trustedCertifiates;

	@Override
	public KeyStore getTrustedCerticiates() throws CertificateManagerException {
		if (this.trustedCertifiates == null)
			throw new CertificateManagerException("Trusted certifiacate key store not set");

		return trustedCertifiates;
	}

	/**
	 * Constructor.
	 * 
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public DefaultCertificateManager() throws CertificateManagerException {

		try {

			// Creating an empty JKS keystore for a trusted certificates
			trustedCertifiates = KeyStore.getInstance(KeyStore.getDefaultType());
			trustedCertifiates.load(null, null);

			// Creating an empty PKCS12 keystore for client certificates
			endEntityCertificates = KeyStore.getInstance("PKCS12");
			endEntityCertificates.load(null, null);

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			if (logger.isErrorEnabled())
				logger.error(e.getMessage(), e);

			throw new CertificateManagerException(e.getMessage(), e);
		}

	}

	/**
	 * Client certificates.
	 */
	private KeyStore endEntityCertificates;

	@Override
	public KeyStore getEndEntityCertificates() throws CertificateManagerException {
		if (this.endEntityCertificates == null)
			throw new CertificateManagerException("End entity certifiacate key store not set");
		return this.endEntityCertificates;
	}

	@Override
	public void importTrustedCertificates(List<X509Certificate> trustedCertificates)
			throws CertificateManagerException {

		// Add certificate chain to the trust store
		int alias = 0;
		for (X509Certificate x509Certificate : trustedCertificates) {

			if (logger.isInfoEnabled())
				logger.info("Adding certificate to the trust store: {}", x509Certificate.getSubjectDN().toString());

			try {

				// Import certificate
				getTrustedCerticiates().setCertificateEntry(Integer.toString(alias), x509Certificate);
				alias++;

			} catch (KeyStoreException e) {
				if (logger.isErrorEnabled())
					logger.error(e.getMessage(), e);

				throw new CertificateManagerException(e.getMessage(), e);
			}
		}

	}

	@Override
	public String exportTrustedCertificates() throws CertificateManagerException {

		// String writter
		StringWriter stringWritter = new StringWriter();

		try {

			// Bouncy castle PEM writter
			PEMWriter pemWritter = new PEMWriter(stringWritter);
			Enumeration<String> aliases = getTrustedCerticiates().aliases();
			List<String> aliasList = Collections.list(aliases);
			for (String alias : aliasList) {
				Certificate certificate = getTrustedCerticiates().getCertificate(alias);
				pemWritter.writeObject(certificate);
			}
			pemWritter.close();

		} catch (KeyStoreException | IOException e) {
			if (logger.isErrorEnabled())
				logger.error(e.getMessage(), e);

			throw new CertificateManagerException(e.getMessage(), e);
		}
		// Return PEM encoded chain
		return stringWritter.toString();
	}

}
