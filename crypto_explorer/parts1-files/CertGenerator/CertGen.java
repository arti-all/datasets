package com.symphony.util;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;

import javax.security.auth.x500.X500Principal;

/**
 * @author tarsillon1
 * @since 26/07/17
 */
public class CertGen {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, CertificateException {
    KeyPair keys = createKeyPair("RSA", 2048);
    X509Certificate certificate = generateCertificate("*.symphony.com", keys, -1);
    writeCert("wildcard", certificate, keys, "/tmp/", "changeit");
  }

  /**
   * Creates a key pair
   * @param encryptionType the encryption type
   * @param byteCount the byte count
   * @return a new key pair
   */
  private static KeyPair createKeyPair(String encryptionType, int byteCount) throws NoSuchProviderException,
      NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(encryptionType, BouncyCastleProvider.PROVIDER_NAME);
    keyPairGenerator.initialize(byteCount);
    return keyPairGenerator.genKeyPair();
  }

  /**
   * Generate an X509 cert for use as the keystore cert chain
   * @return the cert
   */
  private static X509Certificate generateCertificate(String name, KeyPair keys, int daysValid) throws CertificateException {
    X509Certificate cert;

    // backdate the start date by a week
    Calendar start = Calendar.getInstance();
    start.add(Calendar.DATE, -7);
    java.util.Date startDate = start.getTime();

    // what is the end date for this cert's validity?
    Calendar end = Calendar.getInstance();
    end.add(Calendar.DATE, daysValid);
    java.util.Date endDate = end.getTime();

    try {
      X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
          new X500Principal("CN=" + name),
          BigInteger.ONE,
          startDate, endDate,
          new X500Principal("CN=" + name),
          keys.getPublic());

      AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
      AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
      AsymmetricKeyParameter keyParam = PrivateKeyFactory.createKey(keys.getPrivate().getEncoded());
      ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParam);
      X509CertificateHolder certHolder = certBuilder.build(sigGen);

      // now lets convert this thing back to a regular old java cert
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      InputStream certIs = new ByteArrayInputStream(certHolder.getEncoded());
      cert = (X509Certificate) cf.generateCertificate(certIs);
      certIs.close();
    } catch (CertificateException ce) {
      throw new CertificateException("Cert generation failed.");
    } catch (Exception ex) {
      throw new InternalError("Internal error.");
    }

    return cert;
  }

  /**
   * Converts cert to PEM key
   * @param signedCertificate the cert to convert
   * @return the PEM
   */
  private static String convertCertificateToPEM(X509Certificate signedCertificate) throws IOException {
    StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
    pemWriter.writeObject(signedCertificate);
    pemWriter.close();
    return signedCertificatePEMDataStringWriter.toString();
  }

  /**
   * Writes cert to file
   * @param alias the alias to save the cert as
   * @param certificate the certificate to save
   * @param keys the key pair for the cert
   * @param dir the dir to save the cert to
   * @param password the cert password
   */
  private static void writeCert(String alias, Certificate certificate, KeyPair keys, String dir, String password) {
    char[] pw = password.toCharArray();
    Certificate[] outChain = {certificate};
    try {
      KeyStore outStore = KeyStore.getInstance("PKCS12");
      outStore.load(null, pw);
      outStore.setKeyEntry(alias, keys.getPrivate(), pw, outChain);
      OutputStream outputStream = new FileOutputStream(new File(dir, alias + ".p12"));
      outStore.store(outputStream, pw);
      outputStream.flush();
      outputStream.close();
    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
      e.printStackTrace();
    }
  }


}
