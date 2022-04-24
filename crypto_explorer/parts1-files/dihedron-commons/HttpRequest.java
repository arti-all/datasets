/**
 * Copyright (c) 2012-2014, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.patterns.http;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.dihedron.core.strings.Strings;
import org.dihedron.patterns.http.HttpParameter.Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Andrea Funto'
 */
public class HttpRequest {
	
	/**
	 * The logger.
	 */
	private static final Logger logger = LoggerFactory.getLogger(HttpRequest.class);
	
	/**
	 * The internal secure number generator.
	 */
	private static final SecureRandom random = new SecureRandom();

	/**
	 * The request HTTP method (GET, POST...).
	 */
	private HttpMethod method = HttpMethod.GET;
	
	/**
	 * The URL against which the request will be made.
	 */
	private String url;
	
	/**
	 * The request headers map.
	 */
	private Map<String, String> headers = new HashMap<>();
	
	/**
	 * The request parameters' map.
	 */
	private Set<HttpParameter> parameters = new HashSet<>();
	
	/**
	 * Boundary value between parameters in multipart/form-data.
	 */
	private String boundary = new BigInteger(130, random).toString(32);
		
	/**
	 * Constructor.
	 *
	 * @param method
	 *   the HTTP method to use for the request.
	 * @param url
	 *   the URL to send the request to.
	 * @throws MalformedURLException
	 *   if the given URL cannot be parsed. 
	 */
	public HttpRequest(HttpMethod method, URL url) throws MalformedURLException {		
		this(method, url.toExternalForm());
	}
	
	/**
	 * Constructor.
	 *
	 * @param method
	 *   the HTTP method to use for the request.
	 * @param url
	 *   the URL to send the request to.
	 */
	public HttpRequest(HttpMethod method, String url) {
		this.method = method;
		this.url = url;
	}	
	
	/**
	 * Returns the HTTP method of this request.
	 * 
	 * @return
	 *   the HTTP method of this request.
	 */
	HttpMethod getMethod() {
		return method;
	}
	
	/**
	 * Returns the destination URL of this request.
	 * 
	 * @return
	 *   the destination URL of this request.
	 * @throws HttpClientException
	 *   if the parameters of a GET request contain a "FILE" type parameter, which 
	 *   cannot be serialised as a set of ampersand-joined key/value strings.  
	 * @throws MalformedURLException
	 *   if the string representation of the URL cannot be parsed.  
	 */
	URL getURL() throws HttpClientException, MalformedURLException {
		String buffer = url;
		if(method == HttpMethod.GET) {  
			buffer = url + (url.contains("?") ? "&" : "?") + HttpParameter.concatenate(parameters);
		}
		logger.trace("real request URL: '{}'", buffer);
		return new URL(buffer);
	}
	
	/**
	 * Returns the random string to be used as field boundary in MIME
	 * multipart/form-data POST requests.
	 *  
	 * @return
	 *   the random string used as field boundary.
	 */
	public String getBoundary() {
		return boundary;
	}
	
	/**
	 * Returns the map of request headers.
	 * 
	 * @return
	 *   the map of request headers.
	 */
	Map<String, String> getHeaders() {
		return headers;
	}
	
	/**
	 * Sets the value of the given header, replacing whatever was already
	 * in there; if the value is null or empty, the header is dropped 
	 * altogether.
	 * 
	 * @param header
	 *   the name of the header to set.
	 * @param value
	 *   the new value for the header.
	 * @return
	 *   the object itself, for method chaining.
	 */
	public HttpRequest withHeader(String header, String value) {
		if(Strings.isValid(header)) {
			if(Strings.isValid(value)) {
				headers.put(header,  value);
			} else {
				withoutHeader(header);
			}			
		}
		return this;
	}
	
	/**
	 * Resets the value of the given header.
	 * 
	 * @param header
	 *   the name of the header to reset.
	 * @return
	 *  the object itself, for method chaining.
	 */
	public HttpRequest withoutHeader(String header) {
		if(headers.containsKey(header)) {
			headers.remove(header);
		}
		return this;
	}	
	
	/**
	 * Returns the map of request parameters.
	 * 
	 * @return
	 *   the set of request parameters.
	 */
	Collection<HttpParameter> getParameters() {
		return parameters;
	}	

	/**
	 * Sets the value of the given parameter, replacing whatever was 
	 * already in there; if the value is null or empty, the parameter 
	 * is dropped altogether.
	 * 
	 * @param parameter
	 *   the name of the parameter to set.
	 * @param value
	 *   the new value for the parameter.
	 * @return
	 *   the object itself, for method chaining.
	 */
	public HttpRequest withParameter(HttpParameter parameter) {
		if(parameter != null) {
			parameters.add(parameter);
		} else {
			withoutParameter(parameter);			
		}
		return this;
	}
	
	/**
	 * Resets the value of the given parameter.
	 * 
	 * @param parameter
	 *   the name of the parameter to reset.
	 * @return
	 *  the object itself, for method chaining.
	 */
	public HttpRequest withoutParameter(String parameter) {
		if(Strings.isValid(parameter)) {
			for(HttpParameter p : parameters) {
				if(parameter.equals(p.getName())) {
					parameters.remove(p);
				}
			}
		}
		return this;
	}
	
	/**
	 * Resets the value of the given parameter.
	 * 
	 * @param parameter
	 *   the parameter to reset.
	 * @return
	 *  the object itself, for method chaining.
	 */
	public HttpRequest withoutParameter(HttpParameter parameter) {
		if(parameter != null) {
			return withoutParameter(parameter.getName());
		}
		return this;
	}	
	
	/**
	 * Checks if the request has at least one parameter of type FILE,
	 *  which is incompatible with GET requests and must be sent as a
	 *  MIME multipart/form-data.
	 *  
	 * @return
	 *   whether the request contains FILE parameters.
	 */
	boolean isMultiPartFormData() {
		for(HttpParameter parameter : parameters) {
			if(parameter.getType() == Type.FILE) {
				return true;
			}
		}
		return false;
	}
}
