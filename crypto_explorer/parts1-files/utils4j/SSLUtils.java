package com.varra.util;
import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * The Class SSLTool.
 *
 * @author <a href="mailto:Rajakrishna_Reddy@Trimble.com">Rajakrishna V.
 *         Reddy</a>
 * @version 1.0
 */
public class SSLUtils
{
   
   /**
    * Disable certificate validation.
    */
   public static void disableCertificateValidation()
   {
      try
      {
         // Create a trust manager that does not validate certificate chains
         TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
         {
            public X509Certificate[] getAcceptedIssuers()
            {
               return new X509Certificate[0];
            }
            
            public void checkClientTrusted(X509Certificate[] certs, String authType)
            {
            }
            
            public void checkServerTrusted(X509Certificate[] certs, String authType)
            {
            }
         } };
         
         // Ignore differences between given hostname and certificate hostname
         HostnameVerifier hv = new HostnameVerifier()
         {
            
            public boolean verify(String hostname, SSLSession session)
            {
               return true;
            }
         };
         
         // Install the all-trusting trust manager
         try
         {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier(hv);
         }
         catch (Exception e)
         {
         }
      }
      catch (Exception e)
      {
         e.printStackTrace();
      }
   }
}

