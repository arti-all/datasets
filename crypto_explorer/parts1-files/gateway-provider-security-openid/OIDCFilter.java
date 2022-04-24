/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.gateway.openid.filter;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import org.apache.commons.lang3.RandomStringUtils;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class OIDCFilter implements Filter {
  public static final String PARAM_TOKEN_ENDPOINT = "TokenEndpoint";
  public static final String PARAM_AUTHORIZE_ENDPOINT = "AuthorizeEndpoint";
  public static final String PARAM_CLIENT_ID = "ClientId";
  public static final String PARAM_CLIENT_SECRET = "ClientSecret";

  private static final String SESSION_OIDC_STATE = "oidcState";
  private static final String ID_TOKEN = "id_token";
  private static final String NONCE = "nonce";
  private static final String SUB = "sub";
  private static final String OPENID = "openid";

  public static final String ATTRIBUTE_LOGGED_IN = "oidc_login";
  public static final String ATTRIBUTE_ERROR = "oidc_error";
  public static final String ATTRIBUTE_ERROR_DESCRIPTION = "oidc_error_desc";
  public static final String ATTRIBUTE_SUB_ID= "oidc_sub";

  public static final String ERROR_STATE_MISMATCH= "state_mismatch";

  private String tokenEndpoint;
  private String authorizeEndpoint;
  private String clientId;
  private String clientSecret;

  public void init(FilterConfig filterConfig) throws ServletException {
    tokenEndpoint = filterConfig.getInitParameter(PARAM_TOKEN_ENDPOINT);
    authorizeEndpoint = filterConfig.getInitParameter(PARAM_AUTHORIZE_ENDPOINT);
    clientId = filterConfig.getInitParameter(PARAM_CLIENT_ID);
    clientSecret = filterConfig.getInitParameter(PARAM_CLIENT_SECRET);
  }

  public void destroy() {
  }

  /**
   * Persisted credential associated with the current request or {@code null} for none.
   */
  private Credential credential;

  /**
   * Lock on the flow.
   */
  private final Lock lock = new ReentrantLock();

  /**
   * Authorization code flow to be used across all HTTP servlet requests or {@code null} before
   * initialized in {@link #initializeFlow()}.
   */
  private AuthorizationCodeFlow flow;

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
    throws IOException, ServletException {
    //if these aren't http requests, we can't handle this
    if(!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse)) {
      filterChain.doFilter(request, response);
    }
    else {
      HttpServletRequest req = (HttpServletRequest)request;
      HttpServletResponse resp = (HttpServletResponse)response;
      lock.lock();
      try {
        // load credential from persistence store
//        String userId = getUserId(request);
        if(flow == null) {
          flow = initializeFlow();
        }

        //not already logged in, see if this is a redirect back from the IDP or initial request
        if(!processAuthorizationCode(req, resp)) {
          // redirect to the authorization flow
          AuthorizationCodeRequestUrl authorizationUrl = flow.newAuthorizationUrl();
          HttpSession session = ((HttpServletRequest)request).getSession();
          String state = RandomStringUtils.randomAlphanumeric(16);
          //state doesn't necessarily need to be in the session, but it does need to be verified as part of
          //the response from the IDP
          session.setAttribute(SESSION_OIDC_STATE, state);
          authorizationUrl.setState(state);

          authorizationUrl.setRedirectUri(getRedirectUri(req));
          resp.sendRedirect(authorizationUrl.build());
          credential = null;
        }
        else {
          filterChain.doFilter(request, response);
        }
      } finally {
        lock.unlock();
      }
    }
  }

  private boolean processAuthorizationCode(HttpServletRequest req, HttpServletResponse resp)
    throws ServletException, IOException {
    StringBuffer buf = req.getRequestURL();
    String personGuid = null;
    if(req.getQueryString() != null) {
      buf.append('?').append(req.getQueryString());
    }
    AuthorizationCodeResponseUrl responseUrl;

    try {
      responseUrl = new AuthorizationCodeResponseUrl(buf.toString());
    }
    catch (Exception e) {
      return false;
    }
    String code = responseUrl.getCode();
    String state = responseUrl.getState();
    if(responseUrl.getError() != null) {
      //error
      String error = responseUrl.getError();
      String errorDescription = responseUrl.getErrorDescription();
      req.setAttribute(ATTRIBUTE_LOGGED_IN, false);
      req.setAttribute(ATTRIBUTE_ERROR, error);
      req.setAttribute(ATTRIBUTE_ERROR_DESCRIPTION, errorDescription);
      return true;

    }
    else if(code == null) {
      return false;
    }
    else {
      lock.lock();
      try {
        if(flow == null) {
          flow = initializeFlow();
        }

        HttpSession session = req.getSession();
        String storedState = (String)session.getAttribute(SESSION_OIDC_STATE);
        if(state != null && state.equals(storedState)) {
          String redirectUri = getRedirectUri(req);
          SecureRandom random = new SecureRandom();
          byte[] bytes = new byte[16];
          random.nextBytes(bytes);
          Base64 b64 = Base64.encode(bytes);
          String nonce = b64.toString();
          nonce = nonce == null ? "" : nonce;
          String returnedNonce = null;

          TokenRequest tokenRequest = flow.newTokenRequest(code).setRedirectUri(redirectUri);
          tokenRequest.set(NONCE, nonce);
          TokenResponse response = tokenRequest.execute();
          String idToken = (String)response.get(ID_TOKEN);
          System.out.println("id token: " + idToken);

          String[] str = idToken.split("\\.");
          if(str.length == 3) {
            String json = new Base64URL(str[1]).decodeToString();
            String[] outer = json.split("[\\{\\}]");

            for(String s : outer) {
              String[] pairs = s.split(",");
              for(String p : pairs) {
                String[] kv = p.split(":");
                if(kv.length == 2) {
                  String key = null;
                  if(kv[0].startsWith("\"")) {
                    key = kv[0].substring(1, kv[0].length() - 1);
                  }
                  else {
                    key = kv[0];
                  }
                  if(SUB.equals((key))) {
                    if(kv[1].startsWith("\"")) {
                      personGuid = kv[1].substring(1, kv[1].length() - 1);
                    }
                    else {
                      personGuid = kv[1];
                    }
                  }
                  else if(NONCE.equals((key))) {
                    if(kv[1].startsWith("\"")) {
                      returnedNonce = kv[1].substring(1, kv[1].length() - 1);
                    }
                    else {
                      returnedNonce = kv[1];
                    }
                  }
                }
                if(personGuid != null && returnedNonce != null) {
                  break;
                }
              }
              if(personGuid != null && returnedNonce != null) {
                break;
              }
            }
          }

          if(!nonce.equals(returnedNonce)) {
            personGuid = null;
          }
          System.out.println("personguid: " + personGuid);
          String userId = getUserId(req);
//          Credential credential = flow.createAndStoreCredential(response, userId);
          req.setAttribute(ATTRIBUTE_LOGGED_IN, personGuid != null);
          req.setAttribute(ATTRIBUTE_SUB_ID, personGuid);
          return personGuid != null;
        }
        else {
          req.setAttribute(ATTRIBUTE_LOGGED_IN, false);
          req.setAttribute(ATTRIBUTE_ERROR, ERROR_STATE_MISMATCH);
          return true;
        }
//      } catch(ParseException e) {
//        e.printStackTrace();
//      } catch(JOSEException e) {
//        e.printStackTrace();
      } finally {
        lock.unlock();
      }
    }
  }

  /**
   * Loads the authorization code flow to be used across all HTTP servlet requests (only called
   * during the first HTTP servlet request with an authorization code).
   */
  protected AuthorizationCodeFlow initializeFlow() throws ServletException, IOException {
    AuthorizationCodeFlow.Builder builder = 
      new AuthorizationCodeFlow.Builder(BearerToken.authorizationHeaderAccessMethod(),
      new NetHttpTransport(),
      new JacksonFactory(),
      new GenericUrl(tokenEndpoint),
      new BasicAuthentication(clientId, clientSecret),
      clientId,
      authorizeEndpoint);
//    builder.setCredentialDataStore(
//      StoredCredential.getDefaultDataStore(
//        new FileDataStoreFactory(new File("datastoredir"))));
    ArrayList<String> list = new ArrayList<String>();
    list.add(OPENID);
    builder.setScopes(list);
    return builder.build();
  }

  /**
   * Returns the redirect URI for the given HTTP servlet request.
   */
  protected String getRedirectUri(HttpServletRequest httpServletRequest)
    throws ServletException, IOException {
    StringBuffer buf = httpServletRequest.getRequestURL();
//    if(httpServletRequest.getQueryString() != null) {
//      buf.append('?').append(httpServletRequest.getQueryString());
//    }
    GenericUrl url = new GenericUrl(buf.toString());
    return url.build();
  }

  /**
   * Returns the user ID for the given HTTP servlet request.
   */
  protected String getUserId(ServletRequest req) throws ServletException, IOException {
    return "";
  }
}
