package com.symphony.util;

import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

/**
 * Created by lukasz on 01/12/16.
 */
public class CertGenerator {

  private static String caCertFile = "/home/lukasz/Projects/atlas/symphony/global/certs/int-cert.p12";
  private static String caCertPassword = "changeit";
  private static String caKeyFile = "/home/lukasz/Projects/atlas/symphony/global/certs/keys/int-key.pem";
  private static String caKeyPassword = "changeit";

  private static String userAccountName = "test-app";
  private static String userCertDir = "/tmp/";
  private static String userCertPassword = "changeit";

  private static final Date VALID_FROM = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
  private static final Date VALID_TO = new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10));

  private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n";
  private static final String END_CERTIFICATE = "\n-----END CERTIFICATE-----\n";

  public static void main(String[] args) throws Exception {

    parseOptions(args);

    System.out.println(String.format("Generating certificate for %s, using CA cert %s, CA key %s, writing to %s",
        userAccountName, caCertFile, caKeyFile, userCertDir));

    KeyPair keys = generateKeys();
    Certificate[] certChain = createCertChain(Paths.get(caCertFile).toUri(),
        caCertPassword,
        Paths.get(caKeyFile).toUri(),
        caKeyPassword,
        userAccountName,
        keys);
    writeKeystore(userCertDir,
        userCertPassword,
        certChain,
        userAccountName,
        keys);
  }

  private static void usage() {
    System.out.println("Usage: CertGenerator -caCertFile=int-cert.p12 -caCertPassword=changeit " +
        "-caKeyFile=int-key.pem -caKeyPassword=changeit " +
        "-userAccountName=bot.user1 -userCertDir=/tmp/ -userCertPassword=changeit");
  }

  private static void parseOptions(String[] args) {
    if (args.length != 7) {
      usage();
      System.exit(1);
    }

    for (String arg : args) {
      String[] opt = arg.split("=");
      switch (opt[0]) {
        case "-caCertFile":
          caCertFile = opt[1];
          break;
        case "-caCertPassword":
          caCertPassword = opt[1];
          break;
        case "-caKeyFile":
          caKeyFile = opt[1];
          break;
        case "-caKeyPassword":
          caKeyPassword = opt[1];
          break;
        case "-userAccountName":
          userAccountName = opt[1];
          break;
        case "-userCertDir":
          userCertDir = opt[1];
          break;
        case "-userCertPassword":
          userCertPassword = opt[1];
          break;
      }
    }
  }

  private static KeyPair generateKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
    Security.addProvider(new BouncyCastleProvider());
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
    generator.initialize(2048);
    KeyPair keys = generator.generateKeyPair();
    return keys;
  }

  private static Certificate[] createCertChain(URI caCertFile, String caCertPassword, URI caKeyFile,
      String caKeyPassword, String userRef, KeyPair userKeys)
      throws OperatorCreationException, CertificateException, IOException,
      NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
      KeyStoreException, URISyntaxException {
    PrivateKey caKey = readPem(caKeyFile, caKeyPassword);

    Certificate[] chain = new Certificate[3];
    Certificate[] caChain = readKeystore(caCertFile, caCertPassword);
    Certificate subjectCert = createUserCert(caChain,
        caKey,
        userKeys.getPublic(),
        userRef);

    chain[2] = caChain[1];
    chain[1] = caChain[0];
    chain[0] = subjectCert;

    return chain;
  }

  private static PrivateKey readPem(URI filename, String password)
      throws IOException, InvalidKeySpecException,
      NoSuchProviderException, NoSuchAlgorithmException, URISyntaxException {

    Path privateKeyFile = Paths.get(filename); // private key file in PEM format
    PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile.toFile()));
    Object object = pemParser.readObject();
    PEMDecryptorProvider decProv =
        new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
    KeyPair keys;
    if (object instanceof PEMEncryptedKeyPair) {
      keys = converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
    } else {
      keys = converter.getKeyPair((PEMKeyPair) object);
    }
    return keys.getPrivate();
  }

  private static Certificate[] readKeystore(URI keyStoreFile, String keyStorePassword)
      throws CertificateException, IOException, NoSuchAlgorithmException, KeyStoreException {
    KeyStore p12 = KeyStore.getInstance("pkcs12");
    FileInputStream fIn = new FileInputStream(keyStoreFile.getPath());
    try {
      p12.load(fIn, keyStorePassword.toCharArray());
      Certificate[] certChain = p12.getCertificateChain("1");
      return certChain;
    } finally {
      fIn.close();
    }
  }

  private static X509Certificate createUserCert(Certificate[] caChain, PrivateKey caKey, PublicKey userKey,
      String userRef) throws CertificateException, CertIOException, NoSuchAlgorithmException, OperatorCreationException {
    Security.addProvider(new BouncyCastleProvider());

    X509Certificate caCert = (X509Certificate) caChain[0];

    X509CertificateHolder certHolder = new JcaX509CertificateHolder(caCert);
    X500Name caRDN = certHolder.getSubject();

    X500NameBuilder subjectBuilder = new X500NameBuilder();
    subjectBuilder.addRDN(BCStyle.C, caRDN.getRDNs(BCStyle.C)[0].getFirst().getValue());
    subjectBuilder.addRDN(BCStyle.O, caRDN.getRDNs(BCStyle.O)[0].getFirst().getValue());
    subjectBuilder.addRDN(BCStyle.OU, caRDN.getRDNs(BCStyle.OU)[0].getFirst().getValue());
    subjectBuilder.addRDN(BCStyle.CN, userRef);

    X509v3CertificateBuilder v3Bldr = new JcaX509v3CertificateBuilder(caRDN,
        BigInteger.valueOf(3),
        VALID_FROM,
        VALID_TO,
        subjectBuilder.build(),
        userKey);

    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    v3Bldr.addExtension(
        Extension.subjectKeyIdentifier,
        false,
        extUtils.createSubjectKeyIdentifier(userKey));
    v3Bldr.addExtension(
        Extension.authorityKeyIdentifier,
        false,
        extUtils.createAuthorityKeyIdentifier(caCert));

    X509CertificateHolder certHldr = v3Bldr.build(
        new JcaContentSignerBuilder("SHA256WithRSA")
            .setProvider("BC")
            .build(caKey));
    X509Certificate cert = new JcaX509CertificateConverter()
        .setProvider("BC")
        .getCertificate(certHldr);

    PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) cert;
    bagAttr.setBagAttribute(
        PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
        new DERBMPString(userRef));
    bagAttr.setBagAttribute(
        PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
        extUtils.createSubjectKeyIdentifier(userKey));

    return cert;
  }

  private static void writeKeystore(String outDir, String keyStorePassword, Certificate[] chain, String commonName,
      KeyPair keys)
      throws NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException,
      CertificateException {
    PKCS12BagAttributeCarrier bagAttr = (PKCS12BagAttributeCarrier) keys.getPrivate();
    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

    bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(commonName));
    bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
        extUtils.createSubjectKeyIdentifier(keys.getPublic()));

    KeyStore store = KeyStore.getInstance("PKCS12", "BC");
    store.load(null, null);
    store.setKeyEntry(commonName, keys.getPrivate(), null, chain);

    try (FileOutputStream fOut = new FileOutputStream(Paths.get(outDir, commonName + ".p12").toFile())) {
      store.store(fOut, keyStorePassword.toCharArray());
    }

    try (Writer writer = new PrintWriter(Paths.get(outDir, commonName + "-cert.pem").toFile())) {
      writer.write("-----BEGIN CERTIFICATE-----\n");
      writer.write(DatatypeConverter.printBase64Binary(chain[0].getEncoded()).replaceAll("(.{64})", "$1\n"));
      writer.write("\n-----END CERTIFICATE-----\n");
    }
  }

  private static X509Certificate pemToX509(String pem) throws CertificateException {
    String[] tokens = pem.split(BEGIN_CERTIFICATE.trim());
    tokens = tokens[1].split(END_CERTIFICATE.trim());
    byte[] certBytes = DatatypeConverter.parseBase64Binary(tokens[0]);

    CertificateFactory factory = CertificateFactory.getInstance("X.509");

    X509Certificate x509 =
        (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certBytes));
    return x509;
  }

}
