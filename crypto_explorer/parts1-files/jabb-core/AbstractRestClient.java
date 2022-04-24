package net.sf.jabb.spring.rest;

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.support.HttpRequestWrapper;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import com.google.common.base.Throwables;

import net.sf.jabb.spring.rest.CustomHttpRequestRetryHandler.IdempotentPredicate;
import net.sf.jabb.util.parallel.BackoffStrategy;
import net.sf.jabb.util.parallel.WaitStrategy;

/**
 * Template class for REST API client using Spring's <code>RestTemplate</code>.
 * This class is intended to be inherited. Subclass should override the following methods if needed:
 * <ul>
 * 	<li>{@link #buildConnectionManager()}</li>
 * 	<li>{@link #configureConnectionManager(PoolingHttpClientConnectionManager)}</li>
 * 	<li>{@link #configureHttpClient(HttpClientBuilder)}</li>
 * 	<li>{@link #configureRequestFactory(HttpComponentsClientHttpRequestFactory)}</li>
 *  <li>{@link #configureRequestFactory(ClientHttpRequestFactory)}</li>
 * 	<li>{@link #buildRequestRetryHandler()}</li>
 * 	<li>{@link #configureRestTemplate(RestTemplate)}</li>
 * </ul>
 * 
 * Subclass should also set {@link #baseUrl}, and call {@link #initializeRestTemplate()} before {@link #restTemplate} can be used.
 * @author James Hu (Zhengmao Hu)
 *
 */
public abstract class AbstractRestClient {
	//private static final Logger logger = LoggerFactory.getLogger(AbstractRestClient.class);
	
	protected static final String HEADER_AUTHORIZATION = "Authorization";
	protected static final HttpHeaders ACCEPT_JSON;
	protected static final HttpHeaders ACCEPT_AND_OFFER_JSON;
	
	static{
		HttpHeaders tmpHeaders = new HttpHeaders();
		tmpHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
		ACCEPT_JSON = HttpHeaders.readOnlyHttpHeaders(tmpHeaders);
		
		tmpHeaders.setContentType(MediaType.APPLICATION_JSON);
		ACCEPT_AND_OFFER_JSON = HttpHeaders.readOnlyHttpHeaders(tmpHeaders);
	}

	/**
	 * The RestTemplate that will be available after {@link #initializeRestTemplate()} is called.
	 */
	protected RestTemplate restTemplate;
	
	/**
	 * the base URL such as 'https://api.example.com:9443/api/v1'
	 */
	protected String baseUrl;

	/**
	 * The HttpClientConnectionManager behind the {@link #restTemplate}. 
	 * It may be null when the instance is created through {@link #AbstractRestClient(HttpClientConnectionManager)} with null argument
	 * - in that case the instance relies on standard JDK facilities to establish HTTP connections.  
	 */
	protected HttpClientConnectionManager connectionManager;
	
	/**
	 * Constructor. 
	 */
	protected AbstractRestClient(){
	}
	
	/**
	 * Create the HttpClientConnectionManager. Subclass may override this method to create a
	 * customized HttpClientConnectionManager. If the subclass returns null from this method,
	 * then the REST client will rely on standard JDK facilities to establish HTTP connections.
	 * @return	the HttpClientConnectionManager created
	 */
	protected HttpClientConnectionManager buildConnectionManager(){
		return new PoolingHttpClientConnectionManager();
	}
	
	/**
	 * Subclass may override this method to configure PoolingHttpClientConnectionManager.
	 * @param connectionManager the PoolingHttpClientConnectionManager to be configured
	 */
	protected void configureConnectionManager(PoolingHttpClientConnectionManager connectionManager){
		// do nothing
	}
	
	/**
	 * Subclass may override this method to configure HttpClientBuilder.
	 * @param httpClientBuilder the HttpClientBuilder to be configured
	 */
	protected void configureHttpClient(HttpClientBuilder httpClientBuilder){
		// do nothing
	}
	
	/**
	 * Subclass may override this method to configure HttpComponentsClientHttpRequestFactory
	 * Please note that after this method is called, {@link #configureRequestFactory(ClientHttpRequestFactory)} will also be called.
	 * @param requestFactory the HttpComponentsClientHttpRequestFactory to be configured
	 */
	protected void configureRequestFactory(HttpComponentsClientHttpRequestFactory requestFactory){
		// do nothing
	}
	
	/**
	 * Subclass may override this method to configure ClientHttpRequestFactory.
	 * Please note that if the request factory is an instance of PoolingHttpClientConnectionManager, both
	 * {@link #configureRequestFactory(HttpComponentsClientHttpRequestFactory)} and this method will be called.
	 * @param requestFactory the HttpComponentsClientHttpRequestFactory to be configured
	 */
	protected void configureRequestFactory(ClientHttpRequestFactory requestFactory){
		// do nothing
	}
	
	/**
	 * Subclass may override this method to provide a HttpRequestRetryHandler.
	 * Please note that HttpRequestRetryHandler applies to Apache HttpClient only.
	 * {@link #buildRequestRetryHandler(int, BackoffStrategy, WaitStrategy, boolean, boolean, boolean, IdempotentPredicate, Class...)} method 
	 * can be used to create a quite practical HttpRequestRetryHandler
	 * @return  the HttpRequestRetryHandler or null if no retry is desired
	 */
	protected HttpRequestRetryHandler buildRequestRetryHandler(){
		return null;
	}
	
	/**
	 * Subclass may override this method to configure message converters used by the RestTemplate.
	 * @param converters	message converters used by the RestTemplate
	 */
	protected void configureMessageConverters(List<HttpMessageConverter<?>> converters){
		// do nothing
	}
	
	/**
	 * Subclass may override this method to configure RestTemplate.
	 * You may find these methods helpful:
	 * <ul>
	 * 	<li>{@link #buildAddBasicAuthHeaderRequestInterceptor(String, String)}</li>
	 * 	<li>{@link #buildAddHeaderRequestInterceptor(String, String)}</li>
	 *  <li>{@link #buildAddHeadersRequestInterceptor(String, String, String, String)}</li>
	 *  <li>{@link #buildAddHeadersRequestInterceptor(String, String, String, String, String, String)}</li>
	 *  <li>{@link #buildAddHeadersRequestInterceptor(String, String, String, String, String, String, String, String)}</li>
	 * 	<li>{@link #buildAddQueryParameterRequestInterceptor(String, String)}</li>
	 * 	<li>{@link #buildNoErrorResponseErrorHandler()}</li>
	 * 	<li>{@link #buildServerErrorOnlyResponseErrorHandler()}</li>
	 * </ul>
	 * @param restTemplate	the RestTemplate to be configured
	 */
	protected void configureRestTemplate(RestTemplate restTemplate){
		// do nothing
	}
	
	/**
	 * Initialize the RestTemplate internally. In simple usage scenarios, this method
	 * should be called from within the constructor of the subclass.
	 * Or, if running inside a Spring context, subclass may call this method 
	 * from within {@link org.springframework.beans.factory.InitializingBean#afterPropertiesSet()} method.
	 */
	protected void initializeRestTemplate(){
		connectionManager = buildConnectionManager();
		if (connectionManager == null){			// should use JDK rather than HttpClient
			restTemplate = new RestTemplate();
		}else{
			if (connectionManager instanceof PoolingHttpClientConnectionManager){
				configureConnectionManager((PoolingHttpClientConnectionManager)connectionManager);
			}
			HttpRequestRetryHandler retryHandler = buildRequestRetryHandler();
			HttpClientBuilder clientBuilder = HttpClients.custom().setConnectionManager(connectionManager);
			configureHttpClient(clientBuilder);
			clientBuilder.setRetryHandler(retryHandler);
			CloseableHttpClient httpClient = clientBuilder.build();
			
			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
			configureRequestFactory(requestFactory);
			
			restTemplate = new RestTemplate(requestFactory);
		}
		configureRequestFactory(restTemplate.getRequestFactory());
		configureMessageConverters(restTemplate.getMessageConverters());
		configureRestTemplate(restTemplate);
	}

	/**
	 * Load X509 certificate from resources.
	 * Certificates can be in binary or base64 DER/.crt format.
	 * @param resource	the resource name
	 * @return	X509 certificate
	 * @throws CertificateException	if the certificate couldn't be loaded
	 */
	protected X509Certificate loadX509CertificateFromResource(String resource) throws CertificateException{
		InputStream derInputStream = this.getClass().getClassLoader().getResourceAsStream(resource);
		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(derInputStream);
		try {
			derInputStream.close();
		} catch (IOException e) {
			// ignore
		}
		return cert;
	}
	
	/**
	 * Build a keystore with certificates loaded from resource
	 * Certificates can be in binary or base64 DER/.crt format.
	 * @param certResources	the resource names
	 * @return	the key store
	 * @throws KeyStoreException		if the key store couldn't be created
	 * @throws CertificateException		if the certificate couldn't be loaded
	 * @throws NoSuchAlgorithmException	if the algorithm required does not exist
	 * @throws IOException				if the key store cannot be initialized
	 */
	protected KeyStore buildKeyStoreFromResources(String... certResources) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException{
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null);
		for (String res: certResources){
			X509Certificate cert = loadX509CertificateFromResource(res);
			String alias = cert.getSubjectX500Principal().getName();
			keyStore.setCertificateEntry(alias, cert);
		}
		return keyStore;
	}
	
	/**
	 * Build a PoolingHttpClientConnectionManager that trusts certificates loaded from specified resource with specified trust strategy.
	 * If you want the REST client to trust some specific server certificates, you can override {@link #buildConnectionManager()} method
	 * and use this method to build a custom connection manager.
	 * @param trustStrategy	The trust strategy, can be null if the default one should be used. 
	 * 			To always trust self-signed server certificates, use <code>TrustSelfSignedStrategy</code>.
	 * @param hostnameVerifier	The verifier of hostnames, can be null if the default one should be used.
	 * 			To skip hostname verification, use <code>NoopHostnameVerifier</code>
	 * @param certResources	Resources that contains certificates in binary or base64 DER/.crt format.
	 * @return	a PoolingHttpClientConnectionManager
	 */
	protected PoolingHttpClientConnectionManager buildConnectionManager(TrustStrategy trustStrategy, HostnameVerifier hostnameVerifier, String... certResources){
		try {
			KeyStore trustStore = certResources == null || certResources.length == 0 ? null : buildKeyStoreFromResources(certResources);
			SSLContext sslContext = SSLContexts.custom()
					.loadTrustMaterial(trustStore, trustStrategy)
			        .build();
			SSLConnectionSocketFactory sslsf = hostnameVerifier == null ? 
					new SSLConnectionSocketFactory(sslContext) : new SSLConnectionSocketFactory(sslContext, hostnameVerifier);
			Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory> create()
					.register("https", sslsf)
					.register("http", PlainConnectionSocketFactory.getSocketFactory())
					.build();
			return new PoolingHttpClientConnectionManager(socketFactoryRegistry);
		} catch (Exception e) {
			throw Throwables.propagate(e);
		}
	}
	

	/**
	 * Build a <code>HttpRequestRetryHandler</code>.
	 * The returned <code>HttpRequestRetryHandler</code> will not retry on <code>InterruptedIOException</code> and <code>SSLException</code>.
	 * @param retryCount		how many times to retry; 0 means no retries
	 * @param backoffStrategy	how should retries to backoff from previous ones
	 * @param waitStrategy		how should the delay between retries to be implemented
	 * @param requestSentRetryEnabled	true if it's OK to retry requests that have been sent
	 * @param retryUnknownHostException	true if retry should happen after UnknownHostException
	 * @param retryConnectException		true if retry should happen after ConnectException
	 * @param idempotentPredicate		Predicate to decide which requests are considered to be retry-able, 
	 * 									if it is null, only <code>GET</code> requests are considered to be retry-able.
	 * @param excludeExceptions			the IOException types that should not be retried
	 * @return	the <code>HttpRequestRetryHandler</code>
	 */
	protected HttpRequestRetryHandler buildRequestRetryHandler(int retryCount, 
			boolean requestSentRetryEnabled, boolean retryUnknownHostException, boolean retryConnectException, 
			BackoffStrategy backoffStrategy, WaitStrategy waitStrategy,
			IdempotentPredicate idempotentPredicate, Class<? extends IOException>... excludeExceptions){
		List<Class<? extends IOException>> excluded = new ArrayList<Class<? extends IOException>>();
		excluded.add(InterruptedIOException.class);
		excluded.add(SSLException.class);
		if (!retryUnknownHostException){
			excluded.add(UnknownHostException.class);
		}
		if (!retryConnectException){
			excluded.add(ConnectException.class);
		}
		if (excludeExceptions != null){
			for (Class<? extends IOException> claz: excludeExceptions){
				excluded.add(claz);
			}
		}
		return new CustomHttpRequestRetryHandler(retryCount, requestSentRetryEnabled, excluded, backoffStrategy, waitStrategy, idempotentPredicate);
	}
	
	/**
	 * Build a <code>HttpRequestRetryHandler</code>.
	 * The returned <code>HttpRequestRetryHandler</code> will not retry on <code>InterruptedIOException</code> and <code>SSLException</code>.
	 * @param retryCount		how many times to retry; 0 means no retries
	 * @param backoffStrategy	how should retries to backoff from previous ones
	 * @param waitStrategy		how should the delay between retries to be implemented
	 * @param requestSentRetryEnabled	true if it's OK to retry requests that have been sent
	 * @param retryUnknownHostException	true if retry should happen after UnknownHostException
	 * @param retryConnectException		true if retry should happen after ConnectException
	 * @param idempotentPredicate		Predicate to decide which requests are considered to be retry-able, 
	 * 									if it is null, only <code>GET</code> requests are considered to be retry-able.
	 * @return	the <code>HttpRequestRetryHandler</code>
	 */
	protected HttpRequestRetryHandler buildRequestRetryHandler(int retryCount, 
			boolean requestSentRetryEnabled, boolean retryUnknownHostException, boolean retryConnectException, 
			BackoffStrategy backoffStrategy, WaitStrategy waitStrategy,
			IdempotentPredicate idempotentPredicate){
		return buildRequestRetryHandler(retryCount, requestSentRetryEnabled, retryUnknownHostException, retryConnectException, backoffStrategy, waitStrategy, 
				idempotentPredicate, (Class<? extends IOException>[])null);
	}
	
	/**
	 * Create a customized ResponseErrorHandler that ignores HttpStatus.Series.CLIENT_ERROR.
	 * That means responses with status codes like 400/404/401/403/etc are not treated as error, therefore no exception will be thrown in those cases.
	 * Responses with status codes like 500/503/etc will still cause exceptions to be thrown.
	 * @return the ResponseErrorHandler that cares only HttpStatus.Series.SERVER_ERROR
	 */
	protected ResponseErrorHandler buildServerErrorOnlyResponseErrorHandler(){
		return new DefaultResponseErrorHandler(){
			@Override
			protected boolean hasError(HttpStatus statusCode) {
				return statusCode.series() == HttpStatus.Series.SERVER_ERROR;
			}
		};
	}
	
	/**
	 * Create a customized ResponseErrorHandler that ignores all HTTP error codes
	 * That means responses with status codes like 40x/50x/etc are not treated as error, therefore no exception will be thrown in those cases.
	 * @return the ResponseErrorHandler that never throws exception
	 */
	protected ResponseErrorHandler buildNoErrorResponseErrorHandler(){
		return new DefaultResponseErrorHandler(){
			@Override
			protected boolean hasError(HttpStatus statusCode) {
				return false;
			}
		};
	}
	
	static protected class AddQueryParameterRequestInterceptor implements ClientHttpRequestInterceptor{
		private String name;
		private String value;
		public AddQueryParameterRequestInterceptor(String name, String value){
			this.name = name;
			this.value = value;
		}

		@Override
		public ClientHttpResponse intercept(org.springframework.http.HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
			try{
				String originalUriString = request.getURI().toString();
				final URI updatedUri = new URI(originalUriString + 
						(originalUriString.contains("?") ? "&" : "?") 
						+ URLEncoder.encode(name, "UTF-8") + "=" + URLEncoder.encode(value, "UTF-8"));
				HttpRequestWrapper wrapper = new HttpRequestWrapper(request){
					@Override
					public URI getURI() {
						return updatedUri;
					}
				};
	            return execution.execute(wrapper, body);
			}catch(URISyntaxException e){
				e.printStackTrace();
				return execution.execute(request, body);
			}
		}
	}
	
	static protected class AddHeaderRequestInterceptor implements ClientHttpRequestInterceptor{
		private String header;
		private String value;
		public AddHeaderRequestInterceptor(String header, String value){
			this.header = header;
			this.value = value;
		}

		@Override
		public ClientHttpResponse intercept(org.springframework.http.HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
			HttpRequestWrapper wrapper = new HttpRequestWrapper(request);
            wrapper.getHeaders().set(header, value);
            return execution.execute(wrapper, body);
		}
	}
	
	static protected class AddHeadersRequestInterceptor implements ClientHttpRequestInterceptor{
		private String[] headers;
		private String[] values;
		public AddHeadersRequestInterceptor(String[] headers, String[] values){
			this.headers = headers;
			this.values = values;
		}

		@Override
		public ClientHttpResponse intercept(org.springframework.http.HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
			HttpRequestWrapper wrapper = new HttpRequestWrapper(request);
			for (int i = 0; i < headers.length; i ++){
	            wrapper.getHeaders().set(headers[i], values[i]);
			}
            return execution.execute(wrapper, body);
		}
	}
	

	/**
	 * Build a ClientHttpRequestInterceptor that adds a query parameter.
	 * @param name	name of the parameter
	 * @param value	value of the parameter
	 * @return	the ClientHttpRequestInterceptor built
	 */
	protected ClientHttpRequestInterceptor buildAddQueryParameterRequestInterceptor(String name, String value){
		return new AddQueryParameterRequestInterceptor(name, value);
	}

	/**
	 * Build a ClientHttpRequestInterceptor that adds a request header.
	 * @param header	name of the header
	 * @param value		value of the header
	 * @return	the ClientHttpRequestInterceptor built
	 */
	protected ClientHttpRequestInterceptor buildAddHeaderRequestInterceptor(String header, String value){
		return new AddHeaderRequestInterceptor(header, value);
	}

	/**
	 * Build a ClientHttpRequestInterceptor that adds two request headers
	 * @param header1	name of header 1
	 * @param value1	value of header 1
	 * @param header2	name of header 2
	 * @param value2	value of header 2
	 * @return the ClientHttpRequestInterceptor built
	 */
	protected ClientHttpRequestInterceptor buildAddHeadersRequestInterceptor(String header1, String value1, String header2, String value2){
		return new AddHeadersRequestInterceptor(new String[]{header1, header2}, new String[]{value1, value2});
	}

	/**
	 * Build a ClientHttpRequestInterceptor that adds three request headers
	 * @param header1	name of header 1
	 * @param value1	value of header 1
	 * @param header2	name of header 2
	 * @param value2	value of header 2
	 * @param header3	name of header 3
	 * @param value3	value of header 3
	 * @return the ClientHttpRequestInterceptor built
	 */
	protected ClientHttpRequestInterceptor buildAddHeadersRequestInterceptor(String header1, String value1, String header2, String value2, String header3, String value3){
		return new AddHeadersRequestInterceptor(new String[]{header1, header2, header3}, new String[]{value1, value2, value3});
	}
	
	/**
	 * Build a ClientHttpRequestInterceptor that adds three request headers
	 * @param header1	name of header 1
	 * @param value1	value of header 1
	 * @param header2	name of header 2
	 * @param value2	value of header 2
	 * @param header3	name of header 3
	 * @param value3	value of header 3
	 * @param header4	name of the header 4
	 * @param value4	value of the header 4
	 * @return the ClientHttpRequestInterceptor built
	 */
	protected ClientHttpRequestInterceptor buildAddHeadersRequestInterceptor(String header1, String value1, String header2, String value2, String header3, String value3, String header4, String value4){
		return new AddHeadersRequestInterceptor(new String[]{header1, header2, header3, header4}, new String[]{value1, value2, value3, value4});
	}

	/**
	 * Build a ClientHttpRequestInterceptor that adds BasicAuth header
	 * @param user			the user name, may be null or empty
	 * @param password		the password, may be null or empty
	 * @return	the ClientHttpRequestInterceptor built
	 */
	protected ClientHttpRequestInterceptor buildAddBasicAuthHeaderRequestInterceptor(String user, String password){
		return new AddHeaderRequestInterceptor(HEADER_AUTHORIZATION, buildBasicAuthValue(user, password));
	}

	/**
	 * Build a ClientHttpRequestInterceptor that adds BasicAuth header
	 * @param apiKey			the api key
	 * @return	the ClientHttpRequestInterceptor built
	 */
	protected ClientHttpRequestInterceptor buildAddBasicAuthHeaderRequestInterceptor(String apiKey){
		return new AddHeaderRequestInterceptor(HEADER_AUTHORIZATION, buildBasicAuthValue(apiKey));
	}

	/**
	 * Build the value to be used in HTTP Basic Authentication header
	 * @param user			the user name, may be null or empty
	 * @param password		the password, may be null or empty
	 * @return	the value to be used for header 'Authorization'
	 */
	protected String buildBasicAuthValue(String user, String password){
		StringBuilder sb = new StringBuilder();
		if (StringUtils.isNotEmpty(user)){
			sb.append(user);
		}
		if (StringUtils.isNotEmpty(password)){
			if (sb.length() > 0){
				sb.append(':');
			}
			sb.append(password);
		}
		return buildBasicAuthValue(sb.toString());
	}
	
	/**
	 * Build the value to be used in HTTP Basic Authentication header
	 * @param key			the API key
	 * @return	the value to be used for header 'Authorization'
	 */
	protected String buildBasicAuthValue(String key){
		String base64Creds;
		try {
			base64Creds = key == null ? "" : Base64.encodeBase64String(key.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Failed to encode", e);
		}
		return "Basic " + base64Creds;
	}
	
	protected String buildUriString(String partialUri){
		String p1 = StringUtils.trimToEmpty(baseUrl);
		String p2 = StringUtils.trimToEmpty(partialUri);
		String url;
		if (p1.length() > 0 && p1.charAt(p1.length() - 1) == '/' && p2.length() > 0 && p2.charAt(p2.length() - 1) == '/'){
			url = p1 + p2.substring(1);
		}else{
			url = p1 + p2;
		}
		return url;
	}
	
	protected URIBuilder uriBuilder(String partialUri){
		String url = buildUriString(partialUri);
		try {
			return new URIBuilder(url);
		} catch(URISyntaxException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
	}
	
	protected URI buildUri(URIBuilder builder){
		try {
			return builder.build();
		} catch(URISyntaxException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
	}

	protected URI buildUri(String partialUri){
		return buildUri(uriBuilder(partialUri));
	}

	protected URI buildUri(String partialUri, List<NameValuePair> params){
		return buildUri(uriBuilder(partialUri).addParameters(params));
	}

	protected URI buildUri(String partialUri, String name, String value){
		return buildUri(uriBuilder(partialUri).addParameter(name, value));
	}

	protected URI buildUri(String partialUri, String name1, String value1, String name2, String value2){
		return buildUri(uriBuilder(partialUri)
				.addParameter(name1, value1)
				.addParameter(name2, value2));
	}

	protected URI buildUri(String partialUri, String name1, String value1, String name2, String value2, String name3, String value3){
		return buildUri(uriBuilder(partialUri)
				.addParameter(name1, value1)
				.addParameter(name2, value2)
				.addParameter(name3, value3));
	}

	protected URI buildUri(String partialUri, String name1, String value1, String name2, String value2, String name3, String value3, String name4, String value4){
		return buildUri(uriBuilder(partialUri)
				.addParameter(name1, value1)
				.addParameter(name2, value2)
				.addParameter(name3, value3)
				.addParameter(name4, value4));
	}
	
	/**
	 * Make a writable copy of an existing HttpHeaders
	 * @param headers	existing HttpHeaders to be copied
	 * @return	a new HttpHeaders that contains all the entries from the existing HttpHeaders
	 */
	protected HttpHeaders copy(HttpHeaders headers){
		HttpHeaders newHeaders = new HttpHeaders();
		newHeaders.putAll(headers);
		return newHeaders;
	}
	
	/**
	 * Add HTTP Basic Auth header
	 * @param headers	the headers, it must not be a read-only one, if it is, use {@link #copy(HttpHeaders)} to make a writable copy first
	 * @param user			the user name, may be null or empty
	 * @param password		the password, may be null or empty
	 */
	protected void addBasicAuthHeader(HttpHeaders headers, String user, String password){
		headers.add(HEADER_AUTHORIZATION, buildBasicAuthValue(user, password));
	}
	
	/**
	 * Add HTTP Basic Auth header
	 * @param headers	the headers, it must not be a read-only one, if it is, use {@link #copy(HttpHeaders)} to make a writable copy first
	 * @param key		the API key
	 */
	protected void addBasicAuthHeader(HttpHeaders headers, String key){
		headers.add(HEADER_AUTHORIZATION, buildBasicAuthValue(key));
	}
	
	protected <T, D> T post(URI uri, D data, MultiValueMap<String, String> headers, Class<T> responseType){
		return restTemplate.exchange(uri, HttpMethod.POST, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T post(String partialUri, D data, MultiValueMap<String, String> headers, Class<T> responseType){
		return restTemplate.exchange(buildUriString(partialUri), HttpMethod.POST, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T post(URI uri, D data, MultiValueMap<String, String> headers, ParameterizedTypeReference<T> responseType){
		return restTemplate.exchange(uri, HttpMethod.POST, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T post(String partialUri, D data, MultiValueMap<String, String> headers, ParameterizedTypeReference<T> responseType){
		return restTemplate.exchange(buildUriString(partialUri), HttpMethod.POST, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T> T get(URI uri, MultiValueMap<String, String> headers, Class<T> responseType){
		return restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<Void>(headers), responseType).getBody();
	}
	
	protected <T> T get(String partialUri, MultiValueMap<String, String> headers, Class<T> responseType){
		return restTemplate.exchange(buildUriString(partialUri), HttpMethod.GET, new HttpEntity<Void>(headers), responseType).getBody();
	}
	
	protected <T> T get(URI uri, MultiValueMap<String, String> headers, ParameterizedTypeReference<T> responseType){
		return restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<Void>(headers), responseType).getBody();
	}
	
	protected <T> T get(String partialUri, MultiValueMap<String, String> headers, ParameterizedTypeReference<T> responseType){
		return restTemplate.exchange(buildUriString(partialUri), HttpMethod.GET, new HttpEntity<Void>(headers), responseType).getBody();
	}
	
	protected <T, D> T patch(URI uri, D data, MultiValueMap<String, String> headers, Class<T> responseType){
		return restTemplate.exchange(uri, HttpMethod.PATCH, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T patch(String partialUri, D data, MultiValueMap<String, String> headers, Class<T> responseType){
		return restTemplate.exchange(buildUriString(partialUri), HttpMethod.PATCH, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T patch(URI uri, D data, MultiValueMap<String, String> headers, ParameterizedTypeReference<T> responseType){
		return restTemplate.exchange(uri, HttpMethod.PATCH, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T patch(String partialUri, D data, MultiValueMap<String, String> headers, ParameterizedTypeReference<T> responseType){
		return restTemplate.exchange(buildUriString(partialUri), HttpMethod.PATCH, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T put(URI uri, D data, MultiValueMap<String, String> headers, Class<T> responseType){
		return restTemplate.exchange(uri, HttpMethod.PUT, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T put(String partialUri, D data, MultiValueMap<String, String> headers, Class<T> responseType){
		return restTemplate.exchange(buildUriString(partialUri), HttpMethod.PUT, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T put(URI uri, D data, MultiValueMap<String, String> headers, ParameterizedTypeReference<T> responseType){
		return restTemplate.exchange(uri, HttpMethod.PUT, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <T, D> T put(String partialUri, D data, MultiValueMap<String, String> headers, ParameterizedTypeReference<T> responseType){
		return restTemplate.exchange(buildUriString(partialUri), HttpMethod.PUT, new HttpEntity<D>(data, headers), responseType).getBody();
	}
	
	protected <D> void patch(URI uri, D data, MultiValueMap<String, String> headers){
		restTemplate.exchange(uri, HttpMethod.PATCH, new HttpEntity<D>(data, headers), Void.class);
	}
	
	protected <D> void patch(String partialUri, D data, MultiValueMap<String, String> headers){
		restTemplate.exchange(buildUriString(partialUri), HttpMethod.PATCH, new HttpEntity<D>(data, headers), Void.class);
	}
	
	protected <D> void put(URI uri, D data, MultiValueMap<String, String> headers){
		restTemplate.exchange(uri, HttpMethod.PUT, new HttpEntity<D>(data, headers), Void.class);
	}
	
	protected <D> void put(String partialUri, D data, MultiValueMap<String, String> headers){
		restTemplate.exchange(buildUriString(partialUri), HttpMethod.PUT, new HttpEntity<D>(data, headers), Void.class);
	}
	
	protected void delete(URI uri, MultiValueMap<String, String> headers){
		restTemplate.exchange(uri, HttpMethod.DELETE, new HttpEntity<Void>(headers), Void.class);
	}
	
	protected void delete(String partialUri, MultiValueMap<String, String> headers){
		restTemplate.exchange(buildUriString(partialUri), HttpMethod.DELETE, new HttpEntity<Void>(headers), Void.class);
	}
	
	protected void get(URI uri, MultiValueMap<String, String> headers){
		restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<Void>(headers), Void.class);
	}
	
	protected void get(String partialUri, MultiValueMap<String, String> headers){
		restTemplate.exchange(buildUriString(partialUri), HttpMethod.GET, new HttpEntity<Void>(headers), Void.class);
	}
	
}
