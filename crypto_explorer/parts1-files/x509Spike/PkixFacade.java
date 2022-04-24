package org.codice.ddf.certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.*;
import org.bouncycastle.pkcs.bc.BcPKCS12MacCalculatorBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS12PBEOutputEncryptorBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;

import java.io.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

public class PkixFacade {

    private static final long MILLIS_IN_YEAR = 31536000000L;
    private static String BC = BouncyCastleProvider.PROVIDER_NAME;

    public static void main(String[] args) throws Exception {

        //Register Bouncy Castle
        //TODO: Is this even necessary? Couldn't we just use the Oracle implementation?
        registerSecurityProvider();
        printSecurityProviderInfo();


        //Load Demo DDF Certificate Authority's cert
        String cacertFilename = "/Users/aaronhoffer/test/ddf-2.8.0-SNAPSHOT/etc/certs/demoCA/cacert.pem";
        X509Certificate certificateAuthorityCert = loadCertificate(cacertFilename);


        //Load Demo DDF Certificate Authority's private key into memory.
        //TODO: Follow up on that Stack Overflow post and try to load the encrypted private key into memoory.
        String certificateAuthorityKeyNoPassword = "/Users/aaronhoffer/test/ddf-2.8.0-SNAPSHOT/etc/certs/demoCA/private/cakey-nopassword.pem";
        PrivateKey caPrivateKey = pemFile2PrivateKey(certificateAuthorityKeyNoPassword);

        //Generate a public and private keypair for a new certificate
        KeyPair targetKeyPair = getKeyPair();

        //Create the Certificate Signing Request
        X509v3CertificateBuilder csr = getCertificateSigningRequest(getHostname(), targetKeyPair.getPublic(), certificateAuthorityCert);

        //Sign the certificate
        X509Certificate signedCert = signCertificate(csr, caPrivateKey);

        //Check certificate. These methods throw exceptions if the check fails.
        signedCert.checkValidity(new Date());
        signedCert.verify(certificateAuthorityCert.getPublicKey());


        //Write signed certificate to disk as an unencrypted, PEM encoded file.
        //This code is just to check the signed certificate with command line tools like openssl
//        String newCertFname = "/Users/aaronhoffer/test/ddf-2.8.0-SNAPSHOT/etc/certs/newCert.crt";
//        JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(newCertFname));
//        pw.writeObject(cert);
//        pw.close();

        //Create PKCS12 keystore and add cert chain and private key to it.
        PKCS12PfxPdu targetPkcs = createPkcs12(targetKeyPair, signedCert, certificateAuthorityCert, "changeit");
        createP12File(targetPkcs, "changeit", "/Users/aaronhoffer/test/ddf-2.8.0-SNAPSHOT/etc/keystores/new.p12");


        //Load DDF's server keystore, add a new entry, and save it as a new file.
        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(new FileInputStream("/Users/aaronhoffer/test/ddf-2.8.0-SNAPSHOT/etc/keystores/serverKeystore.jks"), "changeit".toCharArray());

//        KeyStore.PrivateKeyEntry - This type of entry holds a cryptographic PrivateKey, which is optionally stored in a
//          protected format to prevent unauthorized access. It is also accompanied by a certificate chain for the corresponding public key.
//        Private keys and certificate chains are used by a given entity for self-authentication.
//        The setKeyEntry method assigns the given key (that has already been protected) to the given alias.
//        If the protected key is of type java.security.PrivateKey, it must be accompanied by a certificate chain certifying the corresponding public key. If the underlying keystore implementation is of type jks, key must be encoded as an EncryptedPrivateKeyInfo as defined in the PKCS #8 standard.
//        If the given alias already exists, the keystore information associated with it is overridden by the given key (and possibly certificate chain).

        //You want certificates to be ordered from yours to CA. Browsers do it for you, but Java does not.
        X509Certificate[] certChain = {signedCert, certificateAuthorityCert};

        //TODO: Replace "fqdn", the alias, with the FQDN of the DDF instance.
        jks.setKeyEntry("fqdn", targetKeyPair.getPrivate(), "changeit".toCharArray(), certChain);

        //This next line is just for testing.
        jks.store(new FileOutputStream("/Users/aaronhoffer/test/ddf-2.8.0-SNAPSHOT/etc/keystores/new.jks"), "changeit".toCharArray());

        //TODO: Delete localhost entry from keystore.

    }//end method


    //Save a signed certificate and its corresponding private key to a file as PKCS12 key store.
    //The PKCS file will be encrypted. The password to decrypt the information is passed in as a parameter.
    static void createP12File(PKCS12PfxPdu pkc12Object, String password, String filename) {
        KeyStore store = null;
        try {
            store = KeyStore.getInstance("pkcs12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        //Next line throws engineLoad(Unknown Source) exception
        //Change JCE to Unlimited Strength policy. Find the old JARS here:
        // /Library/Java/JavaVirtualMachines/jdk1.8.0_45.jdk/Contents/Home/jre/lib/security
        try {
            store.load(new ByteArrayInputStream(pkc12Object.getEncoded()), password.toCharArray());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        try {
            store.store(new FileOutputStream(filename), password.toCharArray());
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }


    //Given a certificate signing request and a CA's private key, return a properly signed X509 certificate
    public static X509Certificate signCertificate(X509v3CertificateBuilder csr, PrivateKey signerPrivateKey) {
        ContentSigner signer = null;
        try {
            signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BC).build(signerPrivateKey);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
        }
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter().setProvider(BC);
        X509CertificateHolder holder = csr.build(signer);
        X509Certificate signedCert = null;
        try {
            signedCert = certificateConverter.getCertificate(holder);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return signedCert;
    }//end method


    public static X509Certificate loadCertificate(String filename) {
        JcaX509CertificateConverter certificateConverter = new JcaX509CertificateConverter().setProvider(BC);
        X509CertificateHolder certHolder = (X509CertificateHolder) getPemObjectFromFile(filename);
        X509Certificate cert = null;
        try {
            cert = certificateConverter.getCertificate(certHolder);
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        return cert;
    }//end method


    private static void registerSecurityProvider() {
        //Register the Bouncy Castle service provider.
        Security.addProvider(new BouncyCastleProvider());
    }


    //Print all the aliases in a keystore to the console.
    public static void dumpAliases(KeyStore ks) {

        Enumeration<String> it = null;
        try {
            it = ks.aliases();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        while (it.hasMoreElements()) {
            System.out.println(it.nextElement());
        }

    }//end method


    //Create certificate signing request
    public static X509v3CertificateBuilder getCertificateSigningRequest(String fqdn, PublicKey subjectPubKey, X509Certificate issuerCert) throws OperatorCreationException, CertificateException {

        //Build subject for the certificate
        X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
        nameBuilder.addRDN(BCStyle.C, "US");  //two letter country code
        nameBuilder.addRDN(BCStyle.CN, fqdn); //common name must be the machine's fully qualified domain name
        X500Name subject = nameBuilder.build();

        //Public constructor methods.
        //  public JcaX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey)
        //  public JcaX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Time notBefore, Time notAfter, X500Name subject, PublicKey publicKey)
        //  public JcaX509v3CertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey)

        X509v3CertificateBuilder csr = new JcaX509v3CertificateBuilder(
                issuerCert,
                BigInteger.valueOf(1),
                new Date(System.currentTimeMillis() - MILLIS_IN_YEAR),
                new Date(System.currentTimeMillis() + MILLIS_IN_YEAR),
                subject,
                subjectPubKey);

        return csr;
    }

    //Create a new RSA key pair.
    private static KeyPair getKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BC);
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    //Does exactly what it says on the tin.
    public static PrivateKey pemFile2PrivateKey(String filename) throws IOException {
        //See to https://tools.ietf.org/html/rfc5208#page-3 learn about the standard describing private key.
/*      "[RFC 5208] describes a syntax for private-key information.
        Private-key information includes a private key for some public-key
        algorithm and a set of attributes.  The document also describes a
        syntax for encrypted private keys.  A password-based encryption
        algorithm (e.g., one of those described in [PKCS#5]) could be used to
        encrypt the private-key information."
*/
        //Get a handle to a local file.
        FileInputStream fis = new FileInputStream(filename);

        //Load and parse PEM object
        PEMParser pemRd = new PEMParser(new InputStreamReader(fis));
        Object objectInPemFile = pemRd.readObject();

        //The magic PEM parser should parser should return and instance of PrivateKeyInfo.
        //If this is a problem, the PEM file is probably password protected.
        PrivateKeyInfo privateKeyInfo = (PrivateKeyInfo) objectInPemFile;

        //Extract private key from key info object.
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BC);
        return converter.getPrivateKey(privateKeyInfo);
    }

    //Does exactly what it says on the tin.
    public static String getHostname() {
        String str = "uninitialized";
        try {
            str = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        return str;
    }//end method

    //Does exactly what it says on the tin.
    private static void printSecurityProviderInfo() {
        //Dump provider information to console.
        Provider[] providers = Security.getProviders();
        System.out.println("------------------------");
        for (Provider each : providers) {
            System.out.println(each.getName() + " - " + each.getInfo());
            System.out.println("------------------------");
        }
    }

    //Given a filename, attempt to return the first PEM object in the file.
    //Die hard is there is an error.
    private static Object getPemObjectFromFile(String filename) {
        PEMParser pem;
        Object firstObjectInFile = null;
        try {
            pem = new PEMParser(new InputStreamReader(new FileInputStream(filename)));
            firstObjectInFile = pem.readObject();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return firstObjectInFile;
    }//end method

    public static PKCS12PfxPdu createPkcs12(KeyPair kp, X509Certificate targetCert, X509Certificate caCert, String passwd)
            throws NoSuchAlgorithmException, IOException, PKCSException {

        //Don't know what these do yet.
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();


        //Create master cert bag. Set friendly name attribute.
        PKCS12SafeBagBuilder taCertBagBuilder = new JcaPKCS12SafeBagBuilder(caCert);
        taCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("ddf demo root ca"));

        //Create target cert bag. Set public key and friendly name attributes.
        PKCS12SafeBagBuilder eeCertBagBuilder = new JcaPKCS12SafeBagBuilder(targetCert);
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("fqdn_public"));
        eeCertBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(kp.getPublic()));

        //Start a DES encrypted bag for public key. (DES? Really? WTF? How do we choose AES?)
        ASN1ObjectIdentifier pkcsIdentifier = PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC;
        CBCBlockCipher blockCipher = new CBCBlockCipher(new DESedeEngine());
        OutputEncryptor encryptor = new BcPKCS12PBEOutputEncryptorBuilder(pkcsIdentifier, blockCipher).build(passwd.toCharArray());
        PKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(kp.getPrivate(), encryptor);
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString("fqdn_private"));
        keyBagBuilder.addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, extUtils.createSubjectKeyIdentifier(kp.getPublic()));

        //Create bags for certificate chain
        PKCS12SafeBag[] certs = new PKCS12SafeBag[2];
        certs[0] = eeCertBagBuilder.build();
        certs[1] = taCertBagBuilder.build();

        // Construct the actual key store
        PKCS12PfxPduBuilder pfxPduBuilder = new PKCS12PfxPduBuilder();
        CBCBlockCipher rc2Cipher = new CBCBlockCipher(new RC2Engine());
        BcPKCS12PBEOutputEncryptorBuilder encryptorBuilder = new BcPKCS12PBEOutputEncryptorBuilder(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, rc2Cipher);
        pfxPduBuilder.addEncryptedData(encryptorBuilder.build(passwd.toCharArray()), certs);
        pfxPduBuilder.addData(keyBagBuilder.build());
        return pfxPduBuilder.build(new BcPKCS12MacCalculatorBuilder(), passwd.toCharArray());
    }
}//end class