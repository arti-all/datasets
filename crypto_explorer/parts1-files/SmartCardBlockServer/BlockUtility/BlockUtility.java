package sec.blockfs.blockutility;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Random;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import pteidlib.PteidException;
import pteidlib.pteid;

public class BlockUtility {
    // cross-module variables
    public static final int KEY_SIZE = 2048;
    public static final String DIGEST_ALGORITHM = "SHA-512";
    public static final int BLOCK_SIZE = 4096;
    public static final int SIGNATURE_SIZE = 128;
    public static final int DIGEST_SIZE = 64;
    public static final String BASE_PATH = "C:\\Temp";

    private static final String REVOKED_LIST_URL = "https://pki.cartaodecidadao.pt/publico/lrc/cc_ec_cidadao_crl001_crl.crl";
    private static final String REVOKED_LIST_FILENAME = "cc_ec_cidadao_crl001_crl.crl";

    private static MessageDigest digestAlgorithm = null;
    private static Signature rsaSignature = null;

    // utility methods
    public static String getKeyString(byte[] contents) {
        String keyString = "";
        int stringSize = 10;
        for (int i = 0; i < contents.length && i < stringSize; ++i) {
            keyString += contents[i];
        }
        return keyString;
    }

    public static byte[] digest(byte[] data) {
        try {
            if (digestAlgorithm == null)
                digestAlgorithm = MessageDigest.getInstance(DIGEST_ALGORITHM);
            else
                digestAlgorithm.reset();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return digestAlgorithm.digest(data);
    }

    public static boolean verifyDataIntegrity(byte[] data, byte[] signature, byte[] publicKeyBytes) {
        try {
            PublicKey publicKey = regeneratePublicKey(publicKeyBytes);
            return verifyDataIntegrity(data, signature, publicKey);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static boolean verifyDataIntegrity(byte[] data, byte[] signature, PublicKey publicKey) {
        try {
            // initialize signing algorithm
            if (rsaSignature == null)
                rsaSignature = Signature.getInstance("SHA1withRSA", "SunRsaSign");

            rsaSignature.initVerify(publicKey);
            rsaSignature.update(data, 0, data.length);

            // verify data integrity
            return rsaSignature.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static PublicKey regeneratePublicKey(byte[] publicKeyBytes)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        return keyFactory.generatePublic(pubKeySpec);
    }

    public static byte[] getCertificateInBytes(int n) throws PteidException, CertificateException {
        return pteid.GetCertificates()[n].certif;
    }

    public static X509Certificate getCertFromByteArray(byte[] certificateEncoded) throws CertificateException {
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(certificateEncoded);
        X509Certificate cert = (X509Certificate) f.generateCertificate(in);
        return cert;
    }

    public static String generateString(int length) {
        String chars = new String("1234567890abcdefghijklmnopqrstuvxyz");// .-,/*-+@#£$%&()=?");
        Random rand = new Random();

        char[] text = new char[length];
        for (int i = 0; i < length; i++) {
            text[i] = chars.charAt(rand.nextInt(chars.length()));
        }
        return new String(text);
    }

    public static void validateCertPath(CertPath certPath) throws DataIntegrityFailureException {
        try {
            // obtain root cert
            List<X509Certificate> certs = (List<X509Certificate>) certPath.getCertificates();
            X509Certificate lastCert = (X509Certificate) certs.get(certs.size() - 1);
            X500Principal rootEntity = lastCert.getIssuerX500Principal();
            final X509Certificate rootCert = BlockUtility.findRootCertificate(rootEntity);

            // validate certificate chain
            TrustAnchor anchor = new TrustAnchor(rootCert, null);
            PKIXParameters params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false);

            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);

            // check if the smartcard certificates were revoked
            checkRevocationList(certs);
        } catch (Exception e) {
            //e.printStackTrace();
            throw new DataIntegrityFailureException("The certificate isn't valid - " + e.getMessage());
        }
    }

    private static X509Certificate findRootCertificate(X500Principal root) throws OperationFailedException {
        try {
            String filename = System.getProperty("java.home") + "/lib/security/cacerts".replace('/', File.separatorChar);
            FileInputStream is = new FileInputStream(filename);
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            String password = "changeit";
            keystore.load(is, password.toCharArray());

            // retrieve the most-trusted CAs from the keystore
            PKIXParameters params = new PKIXParameters(keystore);

            // Get the set of trust anchors, which contain the most-trusted CA certificates
            for (TrustAnchor ta : params.getTrustAnchors()) {
                X509Certificate storedCert = ta.getTrustedCert();
                if (storedCert.getIssuerX500Principal().equals(root)) {
                    return ta.getTrustedCert();
                }
            }
            return null;
        } catch (Exception e) {
            // e.printStackTrace();
            throw new OperationFailedException(e.getMessage());
        }
    }

    private static void checkRevocationList(List<X509Certificate> certs) throws DataIntegrityFailureException {
        try {
            X509CRL crl = getRevocationList();
            Set revokedCerts = crl.getRevokedCertificates();
            for (X509Certificate cert : certs) {
                Iterator it = revokedCerts.iterator();
                while (it.hasNext()) {
                    X509CRLEntry entry = (X509CRLEntry) it.next();
                    BigInteger entrySerialNo = entry.getSerialNumber();
                    BigInteger certSerialNo = cert.getSerialNumber();
                    if (entrySerialNo.equals(certSerialNo)) {
                        throw new DataIntegrityFailureException("Data integrity failure. The certificate is revoked.");
                    }
                }
            }
        } catch (DataIntegrityFailureException e) {
            throw e;
        } catch (Exception e) {
            throw new DataIntegrityFailureException("Couldn't check revoked certificates list. " + e.getMessage());
        }
    }

    private static X509CRL getRevocationList() throws IOException, CRLException, CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        FileInputStream inStream = null;
        try {
            inStream = new FileInputStream(REVOKED_LIST_FILENAME);
        } catch (FileNotFoundException e) {
            System.out.println("Retrieving revoked list remotely");
            URL revokedList = new URL(REVOKED_LIST_URL);
            ReadableByteChannel channel = Channels.newChannel(revokedList.openStream());
            FileOutputStream outStream = new FileOutputStream(REVOKED_LIST_FILENAME);
            outStream.getChannel().transferFrom(channel, 0, Long.MAX_VALUE);
            outStream.close();
            inStream = new FileInputStream(REVOKED_LIST_FILENAME);
        }

        X509CRL crl = (X509CRL) certFactory.generateCRL(inStream);
        inStream.close();
        return crl;
    }
}
