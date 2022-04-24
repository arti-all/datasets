package com.wso2.openam;

import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import org.apache.axiom.om.util.Base64;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.commons.io.IOUtils;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.util.EntityUtils;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.client.ClientProtocolException;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.json.JSONException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.AbstractKeyManager;
import org.wso2.carbon.apimgt.impl.factory.KeyManagerHolder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.apimgt.impl.internal.ServiceReferenceHolder;


/**
 * This class provides the implementation to use "Apis"
 * {@link "https://github.com/OAuth-Apis/apis"} for managing OAuth clients and
 * Tokens needed by WSO2 API Manager.
 */
public class OpenAMAuthClient extends AbstractKeyManager {

    private static final Log log = LogFactory.getLog(OpenAMAuthClient.class);

    Map<String, ClientDetails> clientDetailsMapping = new HashMap<String, ClientDetails>();

    private KeyManagerConfiguration configuration;

    /**
     * {@code APIManagerComponent} calls this method, passing
     * KeyManagerConfiguration as a {@code String}.
     *
     * @param configuration
     *            Configuration as abuildAccessTokenRequestFromOAuthApp
     *            {@link org.wso2.carbon.apimgt.api.model.KeyManagerConfiguration}
     */
    @Override
    public void loadConfiguration(KeyManagerConfiguration configuration) throws APIManagementException {
        this.configuration = configuration;
    }

    /**
     * This method will Register the client in Authorization Server.
     *
     * @param oauthAppRequest
     *            this object holds all parameters required to register an OAuth
     *            Client.
     */
    @Override
    public OAuthApplicationInfo createApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = oauthAppRequest.getOAuthApplicationInfo();

        log.debug("Creating a new oAuthApp in Authorization Server");

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        String registrationEndpoint = config.getParameter(OpenAMClientConstants.CLIENT_REG_ENDPOINT)
                + "?_action=create";

        String ssoCookie = getAuthCookieToken();
        HttpPost httpPut = new HttpPost(registrationEndpoint.trim());
        HttpClient httpClient = getHttpClient();

        BufferedReader reader = null;
        try {
            final String clientName = oAuthApplicationInfo.getClientName();
            final String keyType = (String) oAuthApplicationInfo.getParameter(OpenAMClientConstants.KEY_TYPE);
            final String clientId = clientName+"_"+keyType;
            final String scopes = config.getParameter(OpenAMClientConstants.SCOPES);
            final String grantType = (String) oAuthApplicationInfo.getParameter(OpenAMClientConstants.GRANT_TYPE);
            final String callbackURL = oAuthApplicationInfo.getCallBackURL();
            final String tokenScope = (String) oAuthApplicationInfo.getParameter("tokenScope");
            String tokenScopes[] = new String[1];
            tokenScopes[0] = tokenScope;

            final String salt = generateSaltValue();

            log.debug("The generated clientId value is clientId value is: " + clientId);

            final String clientSecret = generateHmacSHA256Signature(salt, clientId);

            final String jsonPayload = createJsonPayloadFromOauthApplication(oAuthApplicationInfo, config,
                    clientSecret);

            log.debug("Payload for creating new client : " + jsonPayload);

            httpPut.setHeader(OpenAMClientConstants.X_SSO_COOKIE, ssoCookie);
            httpPut.setHeader(OpenAMClientConstants.CONTENT_TYPE, OpenAMClientConstants.APPLICATION_JSON_CONTENT_TYPE);
            httpPut.setEntity(new StringEntity(jsonPayload, OpenAMClientConstants.UTF_8));

            HttpResponse response = httpClient.execute(httpPut);
            int responseCode = response.getStatusLine().getStatusCode();

            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OpenAMClientConstants.UTF_8));

            log.debug("response creating new client : " + responseCode);
            log.debug("response creating new client : " + response);

            // If successful a 201 will be returned.
            if (HttpStatus.SC_CREATED == responseCode) {
                ClientDetails clientDetails = new ClientDetails();
                oAuthApplicationInfo = new OAuthApplicationInfo();
                oAuthApplicationInfo.setClientId(clientId);
                clientDetails.setClientId(clientId);
                clientDetails.setClientName(clientName);
                oAuthApplicationInfo.setClientSecret(clientSecret);
                clientDetails.setClientSecret(clientSecret);
                oAuthApplicationInfo.addParameter("tokenScope", tokenScopes[0]);
                clientDetails.setGrantType(grantType);
                oAuthApplicationInfo.addParameter(OpenAMClientConstants.GRANT_TYPE, grantType);
                clientDetails.setGrantType(grantType);
                oAuthApplicationInfo.setCallBackURL(callbackURL);
                clientDetails.setRedirectURL(callbackURL);
                clientDetailsMapping.put(clientId, clientDetails);
                return oAuthApplicationInfo;
            } else {
                handleException("Some thing wrong here while registering the new client "
                        + "HTTP Error response code is " + responseCode);
            }

        } catch (UnsupportedEncodingException e) {
            handleException("Encoding for the Response not-supported.", e);
        } catch (IOException e) {
            handleException("Error while reading response body ", e);
        } catch (GeneralSecurityException e) {
            handleException("Error while creating consumer secret ", e);
        } finally {
            // close buffer reader.
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            httpClient.getConnectionManager().shutdown();
        }
        return null;
    }

    /**
     * This method will update an existing OAuth Client.
     *
     * @param oauthAppRequest
     *            Parameters to be passed to Authorization Server, encapsulated
     *            as an {@code OAuthAppRequest}
     * @return Details of updated OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo updateApplication(OAuthAppRequest oauthAppRequest) throws APIManagementException {
        return null;
    }

    /**
     * Deletes OAuth Client from Authorization Server.
     *
     * @param consumerKey
     *            consumer key of the OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public void deleteApplication(String consumerKey) throws APIManagementException {

        String configURL = configuration.getParameter(OpenAMClientConstants.CLIENT_REG_ENDPOINT);
        HttpClient client = getHttpClient();

        try {
            configURL += consumerKey;
            HttpDelete httpDelete = new HttpDelete(configURL);

            String ssoCookie = getAuthCookieToken();
            httpDelete.setHeader(OpenAMClientConstants.X_SSO_COOKIE, ssoCookie);
            HttpResponse response = client.execute(httpDelete);
            int responseCode = response.getStatusLine().getStatusCode();
            if (log.isDebugEnabled()) {
                log.debug("Delete application response code :  " + responseCode);
            }
            if (responseCode == HttpStatus.SC_OK ||
                    responseCode == HttpStatus.SC_NO_CONTENT) {
                clientDetailsMapping.remove(consumerKey);
                log.info("OAuth Client for consumer Id " + consumerKey + " has been successfully deleted");
                clientDetailsMapping.remove(consumerKey);
            } else {
                handleException("Problem occurred while deleting client for Consumer Key " + consumerKey);
            }
        } catch (IOException e) {
            handleException("Error while reading response body from Server ", e);
        } finally {
            client.getConnectionManager().shutdown();
        }
    }

    /**
     * This method retrieves OAuth application details by given consumer key.
     *
     * @param consumerKey
     *            consumer key of the OAuth Client.
     * @return an {@code OAuthApplicationInfo} having all the details of an
     *         OAuth Client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo retrieveApplication(String consumerKey) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = new OAuthApplicationInfo();
        try {
            ClientDetails clientDetails = clientDetailsMapping.get(consumerKey);

            if (clientDetails == null || clientDetails.getClientId() == null) {
                return null;
            }
            oAuthApplicationInfo.setClientName(clientDetails.getClientName());
            oAuthApplicationInfo.setClientId(clientDetails.getClientId());
            oAuthApplicationInfo.setCallBackURL(clientDetails.getRedirectURL());
            oAuthApplicationInfo.setClientSecret(clientDetails.getClientSecret());
            oAuthApplicationInfo.addParameter(OpenAMClientConstants.GRANT_TYPE, clientDetails.getGrantType());

        } catch (Exception e) {
            handleException("Something went wrong while retrieving client for consumer key  " + consumerKey, e);
        }
        return oAuthApplicationInfo;
    }

    @Override
    public AccessTokenRequest buildAccessTokenRequestFromOAuthApp(OAuthApplicationInfo oAuthApplication,
                                                        AccessTokenRequest tokenRequest) throws APIManagementException {
        tokenRequest.setClientId(oAuthApplication.getClientId());
        tokenRequest.setClientSecret(oAuthApplication.getClientSecret());
        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        final String scopes = config.getParameter("Scope");
        String[] scopeArr = {scopes};
        tokenRequest.setScope(scopeArr);
        return tokenRequest;
    }

    @Override
    public AccessTokenInfo getNewApplicationAccessToken(AccessTokenRequest tokenRequest) throws APIManagementException {
        String newAccessToken;
        long validityPeriod;
        AccessTokenInfo tokenInfo = null;
        HttpClient client = getHttpClient();
        String configURL = configuration.getParameter(OpenAMClientConstants.TOKEN_ENDPOINT);
        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        if (tokenRequest == null) {
            log.warn("No information available to generate Token.");
            return null;
        }

        String applicationTokenScope = ServiceReferenceHolder.getInstance().getAPIManagerConfigurationService()
                .getAPIManagerConfiguration().getFirstProperty(APIConstants.APPLICATION_TOKEN_SCOPE);

        // When validity time set to a negative value, a token is considered
        // never to expire.
        if (tokenRequest.getValidityPeriod() == OAuthConstants.UNASSIGNED_VALIDITY_PERIOD) {
            // Setting a different -ve value if the set value is -1 (-1 will be
            // ignored by TokenValidator)
            tokenRequest.setValidityPeriod(-2);
        }

        // Generate New Access Token
        HttpPost httpTokpost = new HttpPost(configURL);
        List<NameValuePair> tokParams = new ArrayList<NameValuePair>(5);
        tokParams.add(new BasicNameValuePair(OAuth.OAUTH_GRANT_TYPE, OpenAMClientConstants.DEFAULT_GRANT_TYPE_VALUE));
        tokParams.add(new BasicNameValuePair(OpenAMClientConstants.OAUTH_RESPONSE_EXPIRY_TIME,
                Long.toString(tokenRequest.getValidityPeriod())));
        String introspectionConsumerKey = config.getParameter(OpenAMClientConstants.INTROSPECTION_CK);
        String introspectionConsumerSecret = config.getParameter(OpenAMClientConstants.INTROSPECTION_CS);
        tokParams.add(new BasicNameValuePair(OpenAMClientConstants.CONSUMER_KEY, introspectionConsumerKey));
        tokParams.add(new BasicNameValuePair(OpenAMClientConstants.CONSUMER_SECRET, introspectionConsumerSecret));
        StringBuilder builder = new StringBuilder();
        builder.append(applicationTokenScope);

        for (String scope : tokenRequest.getScope()) {
            builder.append(' ').append(scope);
        }

        tokParams.add(new BasicNameValuePair("scope", builder.toString()));
        String clientId = tokenRequest.getClientId();
        String clientSecret = tokenRequest.getClientSecret();
        String encodedSecret = Base64
                .encode(new String(clientId + ":" + clientSecret).getBytes());
        try {
            httpTokpost.setHeader("Authorization", "Basic " + encodedSecret);
            httpTokpost.setEntity(new UrlEncodedFormEntity(tokParams, "UTF-8"));
            HttpResponse tokResponse = client.execute(httpTokpost);
            HttpEntity tokEntity = tokResponse.getEntity();
            int responseCode = tokResponse.getStatusLine().getStatusCode();
            if (responseCode != HttpStatus.SC_OK) {
                throw new RuntimeException("Error occurred while calling token endpoint: HTTP error code : "
                        + tokResponse.getStatusLine().getStatusCode());
            } else {
                tokenInfo = new AccessTokenInfo();
                String responseStr = EntityUtils.toString(tokEntity);
                org.json.JSONObject obj = new org.json.JSONObject(responseStr);
                newAccessToken = obj.get(OpenAMClientConstants.OAUTH_RESPONSE_ACCESSTOKEN).toString();
                validityPeriod = Long.parseLong(obj.get(OpenAMClientConstants.OAUTH_RESPONSE_EXPIRY_TIME).toString());
                if (obj.has("scope")) {
                    tokenInfo.setScope(((String) obj.get("scope")).split(" "));
                }
                tokenInfo.setAccessToken(newAccessToken);
                tokenInfo.setValidityPeriod(validityPeriod);
            }
        } catch (ClientProtocolException exp) {
            handleException("Error while creating token - Invalid protocol used", exp);
        } catch (UnsupportedEncodingException e) {
            handleException("Error while preparing request for token/revoke APIs", e);
        } catch (IOException e) {
            handleException("Error while creating tokens - " + e.getMessage(), e);
        } catch (JSONException e) {
            handleException("Error while parsing response from token api", e);
        }

        return tokenInfo;
    }

    @Override
    public String getNewApplicationConsumerSecret(AccessTokenRequest accessTokenRequest) throws APIManagementException {
        return null;
    }


    @Override
    public AccessTokenInfo getTokenMetaData(String accessToken) throws APIManagementException {

        AccessTokenInfo tokenInfo = new AccessTokenInfo();
        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();

        String introspectionURL = config.getParameter(OpenAMClientConstants.INTROSPECTION_URL);
        BufferedReader reader = null;

        try {
            String ssoCookie = getAuthCookieToken();
            introspectionURL += accessToken;
            URIBuilder uriBuilder = new URIBuilder(introspectionURL);

            uriBuilder.build();

            HttpGet httpGet = new HttpGet(uriBuilder.build());
            httpGet.setHeader(OpenAMClientConstants.X_SSO_COOKIE, ssoCookie);
            HttpClient client = new DefaultHttpClient();


            HttpResponse response = client.execute(httpGet);
            int responseCode = response.getStatusLine().getStatusCode();

            log.info(responseCode);

            if (log.isDebugEnabled()) {
                log.debug("HTTP Response code : " + responseCode);
            }

            HttpEntity entity = response.getEntity();
            JSONObject parsedObject;
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OpenAMClientConstants.UTF_8));

            if (HttpStatus.SC_OK == responseCode) {
                // pass bufferReader object and get read it and retrieve the
                // parsedJson object
                parsedObject = getParsedObjectByReader(reader);
                log.info("parsedObject"+parsedObject);
                if (parsedObject != null) {

                    Map valueMap = parsedObject;
                    //Object principal = valueMap.get("principal");
                    JSONArray clientIDArray = (JSONArray) valueMap.get(OpenAMClientConstants.CLIENT_ID);
                    if (clientIDArray == null) {
                        tokenInfo.setTokenValid(false);
                        return tokenInfo;
                    }
                    String clientId = (String) clientIDArray.get(0);
                    JSONArray expTimeArray = (JSONArray) valueMap.get("expires_in");
                    Long expiryTimeString = Long.valueOf((String)expTimeArray.get(0));


                    if (expiryTimeString == null) {
                        tokenInfo.setTokenValid(false);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_EXPIRED);
                        return tokenInfo;
                    }

                    long currentTime = System.currentTimeMillis();
                    long expiryTime = expiryTimeString;

                    if (expiryTime > currentTime) {
                        tokenInfo.setTokenValid(true);
                        tokenInfo.setConsumerKey(clientId);
                        tokenInfo.setValidityPeriod(expiryTime - currentTime);
                        // Considering Current Time as the issued time.
                        tokenInfo.setIssuedTime(currentTime);
                        JSONArray scopesArray = (JSONArray) valueMap.get(OpenAMClientConstants.SCOPES);

                        if (scopesArray != null && !scopesArray.isEmpty()) {

                            String[] scopes = new String[scopesArray.size()];
                            for (int i = 0; i < scopes.length; i++) {
                                scopes[i] = (String) scopesArray.get(i);
                            }
                            tokenInfo.setScope(scopes);
                        }
                    } else {
                        tokenInfo.setTokenValid(false);
                        log.info("Invalid Token " + accessToken);
                        tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                        return tokenInfo;
                    }

                } else {
                    log.info("Invalid Token " + accessToken);
                    tokenInfo.setTokenValid(false);
                    tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                    return tokenInfo;
                }
            } // for other HTTP error codes we just pass generic message.
            else {
                log.info("Invalid Token " + accessToken);
                tokenInfo.setTokenValid(false);
                tokenInfo.setErrorcode(APIConstants.KeyValidationStatus.API_AUTH_ACCESS_TOKEN_INACTIVE);
                return tokenInfo;
            }

        } catch (UnsupportedEncodingException e) {
            handleException("The Character Encoding is not supported. " + e.getMessage(), e);
        } catch (ClientProtocolException e) {
            handleException(
                    "HTTP request error has occurred while sending request  to OAuth Provider. " + e.getMessage(), e);
        } catch (IOException e) {
            handleException("Error has occurred while reading or closing buffer reader. " + e.getMessage(), e);
        } catch (URISyntaxException e) {
            handleException("Error occurred while building URL with params." + e.getMessage(), e);
        } catch (ParseException e) {
            handleException("Error while parsing response json " + e.getMessage(), e);
        } finally {
            IOUtils.closeQuietly(reader);
        }
        return tokenInfo;
    }

    @Override
    public KeyManagerConfiguration getKeyManagerConfiguration() throws APIManagementException {
        return configuration;
    }

    @Override
    public OAuthApplicationInfo buildFromJSON(String jsonInput) throws APIManagementException {
        return null;
    }

    /**
     * This method will be called when mapping existing OAuth Clients with
     * Application in API Manager
     *
     * @param appInfoRequest
     *            Details of the OAuth Client to be mapped.
     * @return {@code OAuthApplicationInfo} with the details of the mapped
     *         client.
     * @throws APIManagementException
     */
    @Override
    public OAuthApplicationInfo mapOAuthApplication(OAuthAppRequest appInfoRequest) throws APIManagementException {

        OAuthApplicationInfo oAuthApplicationInfo = appInfoRequest.getOAuthApplicationInfo();
        return oAuthApplicationInfo;
    }

    @Override
    public boolean registerNewResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public Map getResourceByApiId(String apiId) throws APIManagementException {
        return null;
    }

    @Override
    public boolean updateRegisteredResource(API api, Map resourceAttributes) throws APIManagementException {
        return true;
    }

    @Override
    public void deleteRegisteredResourceByAPIId(String apiID) throws APIManagementException {

    }

    @Override
    public void deleteMappedApplication(String s) throws APIManagementException {

    }

    @Override
    public Set<String> getActiveTokensByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public AccessTokenInfo getAccessTokenByConsumerKey(String s) throws APIManagementException {
        return null;
    }

    @Override
    public Map<String, Set<Scope>> getScopesForAPIS(String s) throws APIManagementException {
        return null;
    }

    /**
     * This method can be used to create a JSON Payload out of the Parameters
     * defined in an OAuth Application.
     *
     * @param oAuthApplicationInfo
     *            Object that needs to be converted.
     * @return
     */
    private String createJsonPayloadFromOauthApplication(final OAuthApplicationInfo oAuthApplicationInfo,
                                                         final KeyManagerConfiguration config, final String secret) {
        final Map<String, Object> paramMap = new HashMap<String, Object>();
        final String keyType = (String) oAuthApplicationInfo.getParameter(OpenAMClientConstants.KEY_TYPE);
        final String clientName = oAuthApplicationInfo.getClientName();
        final String clientId = clientName+"_"+keyType;
        final JSONArray clientids = new JSONArray();

        clientids.add(clientId);
        paramMap.put("client_id", clientids);

        final JSONArray realm = new JSONArray();
        realm.add(config.getParameter("Realm"));
        paramMap.put("realm", realm);

        final JSONArray userpassword = new JSONArray();
        userpassword.add(secret);
        paramMap.put("userpassword", userpassword);

        final JSONArray clientType = new JSONArray();
        clientType.add(config.getParameter("ClientType"));
        paramMap.put(OpenAMClientConstants.CLIENT_TYPE_IM, clientType);

        final JSONArray redirectionuri = new JSONArray();
        redirectionuri.add(oAuthApplicationInfo.getCallBackURL());
        paramMap.put(OpenAMClientConstants.REDIRECT_URL_IM, redirectionuri);

        final JSONArray responseType = new JSONArray();
        responseType.add("code");
        responseType.add("token");
        responseType.add("id_token");
        responseType.add("code token");
        responseType.add("token id_token");
        responseType.add("code id_token");
        responseType.add("code token id_token");
        paramMap.put(OpenAMClientConstants.RESPONSE_TYPE_IM, responseType);

        final JSONArray scopes = new JSONArray();
        scopes.add(config.getParameter("Scope"));
        paramMap.put(OpenAMClientConstants.SCOPES_IM, scopes);

        final JSONArray clientNameArr = new JSONArray();
        clientNameArr.add(clientName);
        paramMap.put(OpenAMClientConstants.CLIENT_NAME_IM, clientNameArr);

        log.debug("request" + JSONObject.toJSONString((Map) paramMap));
        return JSONObject.toJSONString((Map) paramMap);
    }

    private static String generateSaltValue() throws NoSuchAlgorithmException {
        byte[] bytes = new byte[16];
        SecureRandom secureRandom = SecureRandom.getInstance(OpenAMClientConstants.RANDOM_ALG_SHA1);
        secureRandom.nextBytes(bytes);
        return Base64.encode(bytes);
    }


    /**
     * Can be used to parse {@code BufferedReader} object that are taken from
     * response stream, to a {@code JSONObject}.
     *
     * @param reader
     *            {@code BufferedReader} object from response.
     * @return JSON payload as a name value map.
     */
    private JSONObject getParsedObjectByReader(BufferedReader reader) throws ParseException, IOException {

        JSONObject parsedObject = null;
        JSONParser parser = new JSONParser();
        if (reader != null) {
            parsedObject = (JSONObject) parser.parse(reader);

        }
        return parsedObject;
    }

    /**
     * common method to throw exceptions.
     *
     * @param msg
     *            this parameter contain error message that we need to throw.
     * @param e
     *            Exception object.
     * @throws APIManagementException
     */
    protected void handleException(String msg, Exception e) throws APIManagementException {
        log.error(msg, e);
        throw new APIManagementException(msg, e);
    }

    /**
     * common method to throw exceptions. This will only expect one parameter.
     *
     * @param msg
     *            error message as a string.
     * @throws APIManagementException
     */
    private void handleException(String msg) throws APIManagementException {
        log.error(msg);
        throw new APIManagementException(msg);
    }

    /**
     *
     * /** This method will return HttpClient object.
     *
     * @return HttpClient object.
     */
    private HttpClient getHttpClient() {
        HttpClient httpClient = new DefaultHttpClient();
        return httpClient;
    }

    private static String generateHmacSHA256Signature(final String data, final String key)
            throws GeneralSecurityException, IOException {
        byte[] hmacData = null;
        try {
            final SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA256");
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKey);
            hmacData = mac.doFinal(data.getBytes("UTF-8"));
            final ByteArrayOutputStream os = new ByteArrayOutputStream();
            final Base64Encoder encoder = new Base64Encoder();
            encoder.encode(hmacData, 0, hmacData.length, (OutputStream) os);
            return os.toString();
        } catch (UnsupportedEncodingException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private String getAuthCookieToken() throws APIManagementException{

        KeyManagerConfiguration config = KeyManagerHolder.getKeyManagerInstance().getKeyManagerConfiguration();
        String registrationEndpoint = config.getParameter(OpenAMClientConstants.OPENAM_AUTH_ENDPOINT);
        HttpPost httpPut = new HttpPost(registrationEndpoint.trim());
        HttpClient httpClient = getHttpClient();

        BufferedReader reader = null;
        try {
            // Create the JSON Payload that should be sent to OAuth Server.

            httpPut.setHeader(OpenAMClientConstants.CONTENT_TYPE, OpenAMClientConstants.APPLICATION_JSON_CONTENT_TYPE);
            String introspectionConsumerKey = config.getParameter(OpenAMClientConstants.INTROSPECTION_CK);
            String introspectionConsumerSecret = config.getParameter(OpenAMClientConstants.INTROSPECTION_CS);
            httpPut.setHeader(OpenAMClientConstants.X_OPENAM_USERNAME, introspectionConsumerKey);
            httpPut.setHeader(OpenAMClientConstants.X_OPENAM_PASSWORD, introspectionConsumerSecret);
            HttpResponse response = httpClient.execute(httpPut);
            int responseCode = response.getStatusLine().getStatusCode();

            HttpEntity entity = response.getEntity();
            reader = new BufferedReader(new InputStreamReader(entity.getContent(), OpenAMClientConstants.UTF_8));

            // If successful a 201 will be returned.
            if (HttpStatus.SC_OK == responseCode) {
                String responseStr = EntityUtils.toString(entity);
                org.json.JSONObject obj = new org.json.JSONObject(responseStr);
                String cookieToken = obj.get(OpenAMClientConstants.TOKEN_ID).toString();

                return cookieToken;

            } else {
                handleException("Some thing wrong here while registering the new client "
                        + "HTTP Error response code is " + responseCode);
            }

        } catch (UnsupportedEncodingException e) {
            handleException("Encoding for the Response not-supported.", e);
        } catch (IOException e) {
            handleException("Error while reading response body ", e);
        } catch (JSONException e) {
            handleException("Error while reading response body ", e);
        }  finally {
            // close buffer reader.
            if (reader != null) {
                IOUtils.closeQuietly(reader);
            }
            httpClient.getConnectionManager().shutdown();
        }
        return null;
    }
}