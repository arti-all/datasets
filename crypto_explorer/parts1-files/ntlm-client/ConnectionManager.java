package org.sample.ntlm.mediator.connection;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.synapse.MessageContext;
import org.sample.ntlm.mediator.NTLMMediator;

public class ConnectionManager {

	private static final Log log = LogFactory.getLog(NTLMMediator.class);

	private static ConnectionManager connectionManager = new ConnectionManager();
	static CustomSSLSocketFactory customSSLSocketFactory = null;

	public static ConnectionManager getInstance(boolean trustchain) throws Exception {
		KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
		trustStore.load(null, null);
		customSSLSocketFactory = new CustomSSLSocketFactory(null,trustchain);
		return connectionManager;
	}

	@SuppressWarnings("null")
	public HttpClient getHttpClient(MessageContext synMgtx, int port, String protocal) throws Exception {
		if (log.isDebugEnabled()) {
			log.debug("NTLM mediator ### entery ##");
		}
		DefaultHttpClient httpclient = null;
		try {
			httpclient = (DefaultHttpClient) customSSLSocketFactory.getNewHttpClient(protocal, port,customSSLSocketFactory);
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			log.debug("NTLM Error SSL ### entery ##", e1);
			throw e1;
		}

		return httpclient;
	}

	public static CustomSSLSocketFactory getCustomSSLSocketFactory() {
		return customSSLSocketFactory;
	}
	
	

}
