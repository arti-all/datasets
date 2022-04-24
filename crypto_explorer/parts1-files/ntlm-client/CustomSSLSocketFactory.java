package org.sample.ntlm.mediator.connection;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpVersion;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HTTP;
import org.wso2.carbon.base.ServerConfiguration;
public class CustomSSLSocketFactory extends SSLSocketFactory {
    SSLContext sslContext = SSLContext.getInstance("TLS");
    boolean trustchain = false;

	public CustomSSLSocketFactory(KeyStore truststore,boolean trustchain) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
        super(truststore);

        if(!trustchain){
        TrustManager tm = new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
        sslContext.init(null, new TrustManager[] { tm }, null);
        }else{
        	TrustManager[] trustManagers = null;
        	TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            try {
            	String keystore = ServerConfiguration.getInstance().getFirstProperty("Security.TrustStore.Location");
            	String password = ServerConfiguration.getInstance().getFirstProperty("Security.TrustStore.Password");
            	System.out.println(keystore+" "+ password);
               	tmf.init(readKeyStore(new FileInputStream(keystore),password));
			} catch (Exception e) {
				
			}
            trustManagers = tmf.getTrustManagers();
            sslContext.init(null, trustManagers, null);
        }

        
    }
	
	private static KeyStore readKeyStore(InputStream is, String storePassword) throws Exception {

        if (storePassword == null) {
            //throw new SSOAgentException("KeyStore password can not be null");
        }

        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(is, storePassword.toCharArray());
            return keyStore;
        } catch (Exception e) {
            //throw new SSOAgentException("Error while loading key store file" , e);
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ignored) {
                    //throw new SSOAgentException("Error while closing input stream of key store");
                }
            }
        }
        return null;
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException, UnknownHostException {
        return sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
    }

    @Override
    public Socket createSocket() throws IOException {
        return sslContext.getSocketFactory().createSocket();
    }
    
    
    public HttpClient getNewHttpClient(String protocal,int port,CustomSSLSocketFactory sf) {
        try {
        	int ssl = protocal.equals("https")?port:443;
        	int nonssl =protocal.equals("http")?port:80;
        	
          
        	 HostnameVerifier hv = new HostnameVerifier() {
                 public boolean verify(String urlHostName, SSLSession session) {
                     return true;
                 }
             };
            //CustomSSLSocketFactory sf = new CustomSSLSocketFactory(trustStore);
            sf.setHostnameVerifier(CustomSSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            HttpParams params = new BasicHttpParams();
            HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
            HttpProtocolParams.setContentCharset(params, HTTP.UTF_8);

            SchemeRegistry registry = new SchemeRegistry();
            registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), nonssl));
            registry.register(new Scheme("https", sf, ssl));

            ClientConnectionManager ccm = new ThreadSafeClientConnManager(params, registry);

            return new DefaultHttpClient(ccm, params);
        } catch (Exception e) {
            return new DefaultHttpClient();
        }
    }

	public boolean isTrustchain() {
		return trustchain;
	}

	public void setTrustchain(boolean trustchain) {
		this.trustchain = trustchain;
	}
    
    
}
