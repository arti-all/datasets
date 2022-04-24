package com.paymentech.orbital.sdk.util.ssl;

import com.paymentech.orbital.sdk.configurator.ConfiguratorIF;
import com.paymentech.orbital.sdk.util.exceptions.InitializationException;
import org.apache.log4j.Logger;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Map;

/**
 * <p><b>Title:</b> SocketFactoryFactory</p> <p>(C)opyright 2007, Chase Paymentech Solutions, LLC. All rights reserved
 * <p/>
 * The copyright notice above does not evidence any actual or intended
 * publication of such source code.
 * Paymentech. The copyright notice above does not evidence any actual or intended publication of such source code.</p>
 * <p><b>Author:</b> Scott Monahan</p><p><b>Description:</b><br><br>
 * A factory for creating a socket factory using custom keystore and truststore files </p>
 */
public class SocketFactoryFactory {

  private static SSLSocketFactory factory = null;

  /**
   * Get a Socket Factory
   *
   * @param configurator The global configurations including loggers
   * @return SSLSocketFactory The factory to be used for creating SSL connections
   * @throws InitializationException if initialization fails
   */
  public static SSLSocketFactory getSocketFactory(ConfiguratorIF configurator) {
    KeyManagerFactory kmf = null;
    TrustManagerFactory tmf = null;
    SSLContext ctx = null;
    String constructionStage = null;

    //Get the logger from the configurator
    Logger engineLogger = configurator.getCommonEngineLogger();

    try {

      // only need to create this factory once
      if (factory == null) {

        //Get the configurations Map from the configurator
        Map configurations = configurator.getConfigurations();

        // initialize the keystore
        constructionStage = "Keystore";
        kmf = initializeKeyStore(configurations);

        // initialize the truststore
        constructionStage = "TrustStore";
        tmf = initializeTrustStore(configurations);

        ctx = SSLContext.getInstance("TLS");
        ctx.init(((kmf == null) ? null : kmf.getKeyManagers()), (tmf == null)
            ? null : tmf.getTrustManagers(), null);
        factory = ctx.getSocketFactory();

      }

    } catch (FileNotFoundException fnfe) {
      engineLogger.error(constructionStage + ", file not found", fnfe);
    } catch (IOException ioe) {
      engineLogger.error(constructionStage + ", IOException", ioe);
    } catch (KeyStoreException ke) {
      engineLogger.error(constructionStage + ", KeyStoreException", ke);
    } catch (UnrecoverableKeyException urke) {
      engineLogger.error(constructionStage + ", UnrecoverableKeyException");
    } catch (CertificateException ce) {
      engineLogger.error(constructionStage + ", CertificateException", ce);
    } catch (NoSuchAlgorithmException nsae) {
      engineLogger.error(constructionStage + ", NoSuchAlgorithmException", nsae);
    } catch (KeyManagementException kme) {
      engineLogger.error(constructionStage + ", KeyManagementException", kme);
    } catch (Exception ex) {
      engineLogger.error(constructionStage + ", Exception occurred during initialization", ex);
    }

    return factory;
  }

  private static KeyManagerFactory initializeKeyStore(Map configurations)
      throws CertificateException, FileNotFoundException, IOException, KeyStoreException,
      NoSuchAlgorithmException, UnrecoverableKeyException {
    KeyManagerFactory kmf = null;
    KeyStore ks = null;

    //Get the keystore and truststore configurations from the configurations Map
    String keystorePassphrase = (String) configurations.get(SSLConstants.KEYSTORE_PASSPHRASE_KEY);
    String keystoreFilename = (String) configurations.get(SSLConstants.KEYSTORE_FILENAME_KEY);

    if (keystorePassphrase != null && keystoreFilename != null
        && keystoreFilename.length() > 0) {

      // Read from the configurations file
      char[] passphrase = keystorePassphrase.toCharArray();

      // Not relying on cacerts. have our own keystore
      // Set up trust/key management
      ks = KeyStore.getInstance("JKS");

      // Open the client public/private key file using the password

      InputStream is = new FileInputStream(keystoreFilename);
      try {
        ks.load(is, passphrase);
      } finally {
        try {
          is.close();
        } catch (Exception e) {
        }
      }


      kmf = KeyManagerFactory.getInstance("SunX509");
      kmf.init(ks, passphrase);
    }

    return kmf;
  }

  private static TrustManagerFactory initializeTrustStore(Map configurations)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException,
      FileNotFoundException, IOException {
    TrustManagerFactory tmf = null;

    String trustStorePassphrase = (String) configurations.get(SSLConstants.TRUSTORE_PASSPHRASE_KEY);
    String trustStoreFilename = (String) configurations.get(SSLConstants.TRUSTORE_FILENAME_KEY);

    if (trustStorePassphrase != null && trustStoreFilename != null
        && trustStoreFilename.length() > 0) {

      char[] tpassphrase = trustStorePassphrase.toCharArray();

      KeyStore trustStore = KeyStore.getInstance("JKS");

      InputStream is = new FileInputStream(trustStoreFilename);
      try {
        trustStore.load(is, tpassphrase);
      } finally {
        try {
          is.close();
        } catch (Exception e) {
        }
      }

      tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

      tmf.init(trustStore);
    }

    return tmf;
  }
}
