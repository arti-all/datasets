package org.gonzalad.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * @author agonzalez
 */
public class Main {

    /** 10 years validity - ouch :) */
    private static final long VALIDITY_PERIOD = 1000L * 60L * 60L * 24L * 365L * 10L;

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, OperatorCreationException,
            CertIOException, CertificateException {

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(4096, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // signers name
        X500Name issuerName = new X500Name("CN=www.mockserver.com, O=MockServer, L=London, ST=England, C=UK");
        // subjects name - the same as we are self signed.
        X500Name subjectName = issuerName;
        // serial
        BigInteger serial = BigInteger.valueOf(new SecureRandom().nextInt());

        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter = new Date(System.currentTimeMillis() + VALIDITY_PERIOD);

        // build a certificate generator
        X509Certificate caCert;
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subjectName, keyPair.getPublic());
        builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        KeyUsage usage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment
                | KeyUsage.dataEncipherment | KeyUsage.cRLSign);
        builder.addExtension(Extension.keyUsage, false, usage);

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        purposes.add(KeyPurposeId.id_kp_serverAuth);
        purposes.add(KeyPurposeId.id_kp_clientAuth);
        purposes.add(KeyPurposeId.anyExtendedKeyUsage);
        builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

        ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
        System.out.println(certificate);

        // X509Certificate cert = signCertificate(builder, keyPair.getPrivate());
        // cert.checkValidity(new Date());
        // cert.verify(keyPair.getPublic());

        //
        // // add some options
        // certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        // certGen.setSubjectDN(new X509Name("dc=name"));
        // certGen.setIssuerDN(dnName); // use the same
        // // yesterday
        // certGen.setNotBefore(new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000));
        // // in 2 years
        // certGen.setNotAfter(new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000));
        // certGen.setPublicKey(keyPair.getPublic());
        // certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        // certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        //
        // // finally, sign the certificate with the private key of the same KeyPair
        // X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");
    }

    private static SubjectKeyIdentifier createSubjectKeyIdentifier(PublicKey publicKey)
            throws OperatorCreationException, CertIOException {
        SubjectPublicKeyInfo subjPubKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(publicKey.getEncoded()));
        DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);
        return x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo);
    }
}
