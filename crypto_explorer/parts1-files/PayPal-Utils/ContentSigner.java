package hk.com.quantum.paypal.encrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

class ContentSigner {

	private static CertificateFactory getCerficationFactory() {
		try {
			return CertificateFactory.getInstance("X509", "BC");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		} catch (NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

	private static PrivateKey getPrivateKey(byte[] prvkey, String exportPass) {
		try {
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
			ks.load(new ByteArrayInputStream(prvkey), exportPass.toCharArray());

			String keyAlias = null;
			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				keyAlias = (String) aliases.nextElement();
			}

			return (PrivateKey) ks.getKey(keyAlias, exportPass.toCharArray());
		} catch (KeyStoreException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		} catch (NoSuchProviderException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		} catch (UnrecoverableKeyException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		} catch (NoSuchAlgorithmException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		} catch (CertificateException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		}
	}

	private static CMSSignedDataGenerator getSignedGenerator(byte[] prvkey,
			byte[] pubcertpem, String exportPass) {

		PrivateKey privateKey = getPrivateKey(prvkey, exportPass);

		// Sign the Data with my signing only key pair
		CMSSignedDataGenerator signedGenerator = new CMSSignedDataGenerator();

		try {
			org.bouncycastle.operator.ContentSigner contentSigner = new JcaContentSignerBuilder(
					"SHA1withRSA").setProvider("BC").build(privateKey);

			CertificateFactory cf = getCerficationFactory();

			// Read the Certificate
			X509Certificate certificate = (X509Certificate) cf
					.generateCertificate(new ByteArrayInputStream(pubcertpem));

			X509CertificateHolder certHolder = new JcaX509CertificateHolder(
					certificate);
			signedGenerator
					.addSignerInfoGenerator(new SignerInfoGeneratorBuilder(
							new BcDigestCalculatorProvider()).build(
							contentSigner, certHolder));

			signedGenerator
					.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
							new JcaDigestCalculatorProviderBuilder()
									.setProvider("BC").build()).build(
							contentSigner, certHolder));
			return signedGenerator;
		} catch (CertificateException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		} catch (OperatorCreationException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		}
	}

	static byte[] signData(byte[] privKey, byte[] pubcertpem,
			String exportPass, byte[] data) {
		// Sign the Data with my signing only key pair
		CMSSignedDataGenerator signedGenerator = getSignedGenerator(privKey,
				pubcertpem, exportPass);

		CMSProcessableByteArray cmsByteArray = new CMSProcessableByteArray(data);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();

		try {
			cmsByteArray.write(baos);

			CMSSignedData signedData = signedGenerator.generate(cmsByteArray,
					true);

			return signedData.getEncoded();
		} catch (CMSException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		} catch (IOException e) {
			throw new Error("Program Error: " + e.getMessage(), e);
		}
	}
}
