/*
* Copyright 2016 Axibase Corporation or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
* https://www.axibase.com/atsd/axibase-apache-2.0.pdf
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/
package com.axibase.tsd.driver.jdbc.protocol;

import com.axibase.tsd.driver.jdbc.content.ContentDescription;
import com.axibase.tsd.driver.jdbc.content.json.QueryDescription;
import com.axibase.tsd.driver.jdbc.content.json.SendCommandResult;
import com.axibase.tsd.driver.jdbc.enums.Location;
import com.axibase.tsd.driver.jdbc.enums.MetadataFormat;
import com.axibase.tsd.driver.jdbc.ext.AtsdConnectionInfo;
import com.axibase.tsd.driver.jdbc.ext.AtsdException;
import com.axibase.tsd.driver.jdbc.ext.AtsdRuntimeException;
import com.axibase.tsd.driver.jdbc.intf.IContentProtocol;
import com.axibase.tsd.driver.jdbc.logging.LoggingFacade;
import com.axibase.tsd.driver.jdbc.util.IOUtils;
import com.axibase.tsd.driver.jdbc.util.JsonMappingUtil;
import lombok.SneakyThrows;
import org.apache.calcite.avatica.org.apache.commons.codec.binary.Base64;
import org.apache.calcite.avatica.org.apache.http.HttpHeaders;
import org.apache.calcite.avatica.org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.calcite.avatica.org.apache.http.entity.ContentType;
import org.apache.calcite.runtime.TrustAllSslSocketFactory;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.SocketException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.zip.GZIPInputStream;

import static com.axibase.tsd.driver.jdbc.DriverConstants.*;

public class SdkProtocolImpl implements IContentProtocol {
	private static final LoggingFacade logger = LoggingFacade.getLogger(SdkProtocolImpl.class);
	private static final String POST_METHOD = "POST";
	private static final String GET_METHOD = "GET";
	private static final String CONTEXT_INSTANCE_TYPE = "SSL";
	private static final int CHUNK_LENGTH = 100;

	private final ContentDescription contentDescription;
	private HttpURLConnection conn;
	private String atsdQueryId;
	private String queryId;

	public SdkProtocolImpl(final ContentDescription contentDescription) {
		this.contentDescription = contentDescription;
	}

	@Override
	public InputStream readInfo() throws AtsdException, IOException {
		contentDescription.addRequestHeadersForDataFetching();
		return executeRequest(GET_METHOD, 0, contentDescription.getEndpoint());
	}

	@Override
	public InputStream readContent(int timeoutMillis) throws AtsdException, IOException {
		contentDescription.addRequestHeadersForDataFetching();
		contentDescription.initDataFetchingContent();
		InputStream inputStream = null;
		try {
			inputStream = executeRequest(POST_METHOD, timeoutMillis, contentDescription.getEndpoint());
			if (MetadataFormat.EMBED == contentDescription.getMetadataFormat()) {
				inputStream = MetadataRetriever.retrieveJsonSchemeAndSubstituteStream(inputStream, contentDescription);
			}
		} catch (IOException e) {
			logger.warn("Metadata retrieving error", e);
			if (queryId != null) { // queryId is set if cancel method is invoked from another thread
				throw new AtsdRuntimeException(prepareCancelMessage());
			}
			if (e instanceof SocketException) {
				throw e;
			}
		}
		return inputStream;
	}

	private String prepareCancelMessage() {
		if (atsdQueryId != null) {
			return "Query with driver-generated id=" + queryId +
					" has been cancelled. ATSD queryId is " + atsdQueryId;
		} else {
			return "Disconnect occurred while executing query with driver-generated id=" + queryId;
		}
	}

	@Override
	public void cancelQuery() throws AtsdException, IOException {
        contentDescription.addRequestHeadersForDataFetching();
        String cancelEndpoint = Location.CANCEL_ENDPOINT.getUrl(contentDescription.getInfo()) + '?' + QUERY_ID_PARAM_NAME + '=' + queryId;
		InputStream result = executeRequest(GET_METHOD, 0, cancelEndpoint);
		try {
			final QueryDescription[] descriptionArray = JsonMappingUtil.mapToQueryDescriptionArray(result);
			if (descriptionArray.length > 0) {
				atsdQueryId = descriptionArray[0].getAtsdQueryId();
				queryId = descriptionArray[0].getQueryId();
			}
		} catch (IOException e){
			if (logger.isDebugEnabled()) {
				logger.debug("Wrong query description format", e);
			}
			queryId = contentDescription.getQueryId();
		}
	}

	@Override
	public long writeContent(int timeoutMillis) throws AtsdException, IOException {
		contentDescription.addRequestHeader(HttpHeaders.ACCEPT, PLAIN_AND_JSON_MIME_TYPE);
		contentDescription.addRequestHeader(HttpHeaders.CONTENT_TYPE, ContentType.TEXT_PLAIN.getMimeType());
		long writeCount = 0;
		try {
			InputStream inputStream = executeRequest(POST_METHOD, timeoutMillis, contentDescription.getEndpoint());
			final SendCommandResult sendCommandResult = JsonMappingUtil.mapToSendCommandResult(inputStream);
			logger.trace("[response] content: {}", sendCommandResult);
			if (StringUtils.isNotEmpty(sendCommandResult.getError())) {
				throw new AtsdException("ATSD server error: " + sendCommandResult.getError());
			}
			writeCount = sendCommandResult.getSuccess();
			logger.debug("[response] success: {}", sendCommandResult.getSuccess());
		} catch (IOException e) {
			if (logger.isDebugEnabled()) {
				logger.debug("Data writing error", e);
			}
			if (queryId != null) {
				throw new AtsdRuntimeException(prepareCancelMessage());
			}
			if (e instanceof SocketException) {
				throw e;
			}
		}
		return writeCount;
	}

	@Override
	public void close() {
		if (logger.isTraceEnabled()) {
			logger.trace("[SdkProtocolImpl#close]");
		}
		if (this.conn != null) {
			this.conn.disconnect();
		}
	}

	private InputStream executeRequest(String method, int queryTimeoutMillis, String url) throws AtsdException, IOException {
		if (logger.isDebugEnabled()) {
			logger.debug("[request] {} {}", method, url);
		}
		this.conn = getHttpURLConnection(url);
		if (contentDescription.getInfo().secure()) {
			doTrustToCertificates((HttpsURLConnection) this.conn);
		}
		setBaseProperties(method, queryTimeoutMillis);
		if (MetadataFormat.HEADER == contentDescription.getMetadataFormat()
				&& StringUtils.isEmpty(contentDescription.getJsonScheme())) {
			MetadataRetriever.retrieveJsonSchemeFromHeader(conn.getHeaderFields(), contentDescription);
		}
		if (logger.isDebugEnabled()) {
			logger.debug("[response] length: {}", conn.getContentLengthLong());
		}

		final boolean gzipped = COMPRESSION_ENCODING.equals(conn.getContentEncoding());
		final int code = conn.getResponseCode();
		final InputStream body = code == HttpsURLConnection.HTTP_OK ? conn.getInputStream() : handleErrorCode(conn.getErrorStream(), code);
		return gzipped ? new GZIPInputStream(body) : body;
	}

	private InputStream handleErrorCode(InputStream inputStream, int responseCode) throws AtsdException {
		byte[] bodyAsBytes = ArrayUtils.EMPTY_BYTE_ARRAY;
		String bodyAsString = "";
		String errorMessage = "HTTP code " + responseCode;
		try {
		    if (inputStream != null) {
                bodyAsBytes = IOUtils.inputStreamToByteArray(inputStream);
                bodyAsString = new String(bodyAsBytes);
                logger.debug("Response code: {}, error: {}", responseCode, bodyAsString);
                if (!StringUtils.startsWith(bodyAsString, "#")) {
                    errorMessage = JsonMappingUtil.deserializeErrorObject(bodyAsString);
                    if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED && errorMessage != null) {
                        final int length = errorMessage.length();
                        final String authorizationErrorCode = errorMessage.substring(length - 2, length);
                        final String resolvedMessage = resolveAuthenticationErrorMessageFromCode(authorizationErrorCode);
                        throw new AtsdException("Authentication failed: " + resolvedMessage);
                    }
                }
            }
		} catch (IOException e) {
			errorMessage = "HTTP code " + responseCode + ": " + bodyAsString;
		}
		if (responseCode != HttpURLConnection.HTTP_BAD_REQUEST || !StringUtils.startsWith(bodyAsString, "#")) { // code 400 is processed later
			throw new AtsdRuntimeException(errorMessage);
		}
		return new ByteArrayInputStream(bodyAsBytes);
	}

	private void setBaseProperties(String method, int queryTimeoutMillis) throws IOException {
		final String login = contentDescription.getInfo().user();
		final String password = contentDescription.getInfo().password();
		if (!StringUtils.isEmpty(login) && !StringUtils.isEmpty(password)) {
			final String basicCreds = login + ':' + password;
			final byte[] encoded = Base64.encodeBase64(basicCreds.getBytes());
			conn.setRequestProperty(HttpHeaders.AUTHORIZATION, AUTHORIZATION_TYPE + new String(encoded));
		}
		conn.setAllowUserInteraction(false);
		conn.setConnectTimeout(contentDescription.getInfo().connectTimeoutMillis());
		conn.setDoInput(true);
		conn.setInstanceFollowRedirects(true);
		final int readTimeoutInMillis = getQueryTimeoutMillis(queryTimeoutMillis, contentDescription.getInfo());
		conn.setReadTimeout(readTimeoutInMillis);
		conn.setRequestMethod(method);
		conn.setRequestProperty(HttpHeaders.CONNECTION, CONN_KEEP_ALIVE);
		conn.setRequestProperty(HttpHeaders.USER_AGENT, USER_AGENT);
		conn.setUseCaches(false);
		setAdditionalRequestHeaders(contentDescription.getRequestHeaders());
		if (method.equals(POST_METHOD)) {
			final String postContent = contentDescription.getPostContent();
			conn.setRequestProperty(HttpHeaders.ACCEPT_ENCODING, COMPRESSION_ENCODING);
			conn.setChunkedStreamingMode(CHUNK_LENGTH);
			conn.setDoOutput(true);
			if (logger.isDebugEnabled()) {
				logger.debug("[content] {}",  postContent);
			}
			try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream(), DEFAULT_CHARSET.name()))) {
				writer.write(postContent);
				writer.flush();
			}
		} else {
			conn.setRequestProperty(HttpHeaders.ACCEPT_ENCODING, DEFAULT_ENCODING);
		}
	}

	private static int getQueryTimeoutMillis(int timeoutMillis, AtsdConnectionInfo info) {
		return timeoutMillis == 0 ? info.readTimeoutMillis() : timeoutMillis;
	}

	private static HttpURLConnection getHttpURLConnection(String uri) throws IOException {
		final URL url = new URL(uri);
		return (HttpURLConnection) url.openConnection();
	}

	@SneakyThrows(NoSuchAlgorithmException.class)
	private void doTrustToCertificates(final HttpsURLConnection sslConnection) {
		if (contentDescription.getInfo().trustCertificate()) {
			sslConnection.setSSLSocketFactory(TrustAllSslSocketFactory.getDefaultSSLSocketFactory());
			sslConnection.setHostnameVerifier(NoopHostnameVerifier.INSTANCE);
		} else {
			SSLContext sslContext = SSLContext.getInstance(CONTEXT_INSTANCE_TYPE);
			try {
				sslContext.init(null, null, new SecureRandom());
				sslConnection.setSSLSocketFactory(sslContext.getSocketFactory());
			} catch (KeyManagementException e) {
				logger.error(e.getMessage(), e);
			}
		}
	}

	private void setAdditionalRequestHeaders(Map<String, String> headers) {
		for (Map.Entry<String, String> header : headers.entrySet()) {
			conn.setRequestProperty(header.getKey(), header.getValue());
		}
	}

	private String resolveAuthenticationErrorMessageFromCode(String code) {
		switch (code) {
			// skip 01
			case "02": return "Username Not Found";
			case "03": return "Bad Credentials";
			case "04": return "Disabled LDAP Service";
			case "05": return "Corrupted Configuration";
			case "06": return "MS Active Directory";
			case "07": return "Account Disabled";
			case "08": return "Account Expired";
			case "09": return "Account Locked";
			case "10": return "Logon Not Permitted At Time";
			case "11": return "Logon Not Permitted At Workstation";
			case "12": return "Password Expired";
			case "13": return "Password Reset Required";
			case "14": return "Wrong IP Address";
			case "15": return "Access Denied";
			default: return "Wrong credentials provided";
		}
	}

}
