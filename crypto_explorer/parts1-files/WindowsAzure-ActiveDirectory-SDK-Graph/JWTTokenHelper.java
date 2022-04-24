package com.microsoft.windowsazure.activedirectory.sdk.graph.token;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import javax.crypto.BadPaddingException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONException;
import org.json.JSONObject;

import com.microsoft.windowsazure.activedirectory.sdk.graph.config.SdkConfig;
import com.microsoft.windowsazure.activedirectory.sdk.graph.exceptions.SdkException;
import com.microsoft.windowsazure.activedirectory.sdk.graph.helper.HttpClientHelper;
import com.microsoft.windowsazure.activedirectory.sdk.graph.helper.JSONHelper;
//import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
//import com.sun.org.apache.xml.internal.security.utils.Base64;
import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;



/**
 * Facilitates minting a test token.
 * @author t-mislam
 *
 */
public class JWTTokenHelper {
	
	
	private static Logger logger  = Logger.getLogger(JWTTokenHelper.class);
    /**
     * Grant type claim
     */ 
    private static final String claimTypeGrantType = "grant_type";

    /**
     * Assertion Claim.
     */
    private static final String claimTypeAssertion = "assertion";

    /**
     * Resource Claim.
     */
    private static final String claimTypeResource = "resource";

    /**
     * Prefix for bearer tokens.
     */
    private static final String bearerTokenPrefix = "Bearer ";

	
    JWTTokenHelper(){
    //	PropertyConfigurator.configure("log4j.properties");
    }
    
    
    /**
     * Get the formatted Service Principal Name
     * @param principalName Principal Identifier
     * @param hostName Service Host Name
     * @param realm Tenant Realm.
     * @return The formatted SPN.
     */
	public static String getFormattedPrincipal(String principalName, String hostName, String realm){

		if((hostName != null) && (realm != null)){
			return String.format("%s/%s@%s", principalName, hostName, realm);
		}else if((realm == null) || (realm.isEmpty()) || (realm.trim().isEmpty())){
			return String.format("%s/%s", principalName, hostName);
		}else{
			return String.format("%s@%s", principalName, realm);
		}		
		
	}
	
	/**
	 * Returns the starting Unix Epoch Time.
	 * @return the Unix Epoch Time.
	 */
	public static Date getUnixEpochDateTime() {
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		calendar.set(1970, 0, 1, 0, 0, 0);
		return calendar.getTime();
	}
	
	/**
	 * Returns the current Date Time in UTC.
	 * @return The current time in UTC.
	 */
	public static Date getCurrentDateTime() {
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		return calendar.getTime();
	}

	/**
	 * Add seconds to an existing date time object.
	 * @param seconds Seconds to be added.
	 * @return The new Date Time Object.
	 */
	public static Date addSecondsToCurrentTime(int seconds) {
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		calendar.add(Calendar.SECOND, seconds);
		return calendar.getTime();
		
	}


	/**
	 * Generate access token with a symmetric signing key.
	 * @param webToken JSON Web Token.
	 * @param signingKey Symmetric signing key.
	 * @return Self Signed Assertion.
	 * @throws SdkException If the operation is not successful.
	 */
	public static String generateAssertion(JsonWebToken webToken,
			String signingKey) throws SdkException  {

		TokenHeader tokenHeaderContract = new TokenHeader("HS256", "");
		String tokenHeader = Base64Utils.encode(tokenHeaderContract.encodeToJson());				
		String tokenBody = Base64Utils.encode(webToken.encodeToJson());
		
		String rawToken = String.format("%s.%s", tokenHeader, tokenBody);		
		String signature = Base64Utils.encode(JWTTokenHelper.signData(signingKey, rawToken));				
		String accessToken = String.format("%s.%s", rawToken, signature);		
		return accessToken;
	}

	
	/**
	 * Sign the text with the symmetric key.
	 * @param signingKey The Signing Key.
	 * @param rawToken The rawToken that needs to be signed.
	 * @return Signed byte array.
	 * @throws SdkException
	 */
	private static byte[] signData(String signingKey, String rawToken) throws SdkException {
		SecretKeySpec secretKey = null;
		secretKey = new SecretKeySpec((byte[]) Base64.decodeBase64(signingKey.getBytes()), "HmacSHA256");
		Mac mac;
		byte[] signedData = null;
		
		try {
			mac = Mac.getInstance("HmacSHA256");
			mac.init(secretKey);
			mac.update(rawToken.getBytes("UTF-8"));
			signedData = mac.doFinal();
			
		} catch (Exception e) {
			throw new SdkException(SdkConfig.ErrorGeneratingToken, SdkConfig.ErrorGeneratingTokenMessage, e);
		}		
		return signedData;
	}


	/**
	 * Get an access token from ACS (STS).
	 * @param stsUrl ACS STS Url.
	 * @param assertion Assertion Token.
	 * @param resource ExpiresIn name.
	 * @return The OAuth access token.
	 * @throws SdkException If the operation can not be completed successfully.
	 */
	public static String getOAuthAccessTokenFromACS(String stsUrl,
			String assertion, String resource) throws SdkException {
		
		String accessToken = "";
				
		URL url = null;
		
		String data = null;
		
		try {
			data = URLEncoder.encode(JWTTokenHelper.claimTypeGrantType, "UTF-8") + "=" + URLEncoder.encode("http://oauth.net/grant_type/jwt/1.0/bearer", "UTF-8");
			data += "&" + URLEncoder.encode(JWTTokenHelper.claimTypeAssertion, "UTF-8") + "=" + URLEncoder.encode(assertion, "UTF-8");
			data += "&" + URLEncoder.encode(JWTTokenHelper.claimTypeResource, "UTF-8") + "=" + URLEncoder.encode(resource, "UTF-8");
			
			url = new URL(stsUrl);
			
			URLConnection conn = url.openConnection();
			
			conn.setDoOutput(true);
			
			OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
			wr.write(data);
			wr.flush();
			
			BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			
			String line, response = "";
			
			while((line=rd.readLine()) != null){
				response += line;
			}
			
			wr.close();
			rd.close();
			
			
			accessToken = (new JSONObject(response)).optString("access_token");		
			logger.info("accessToken ->" +  String.format("%s%s", JWTTokenHelper.bearerTokenPrefix, accessToken));
			return String.format("%s%s", JWTTokenHelper.bearerTokenPrefix, accessToken);
			
		} catch (Exception e2) {
			throw new SdkException(SdkConfig.ErrorGeneratingToken, SdkConfig.ErrorGeneratingTokenMessage, e2);
		}
	}
	
	
	public static String GetTokenFromUrl(String acsUrl, String tenantContextId, String appPrincipalId,
			String protectedResourceHostName, String password) throws SdkException{
		
		String accessToken = "";
		HttpURLConnection conn = null;
		try {
			String uri = acsUrl +  "/" + tenantContextId + "/oauth2/token?api-version=1.0";
			URL url = new URL(uri);
			System.out.println("url ->" + url);
			conn = (HttpURLConnection) url.openConnection();
			//    HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
			//   System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
			String postData = "grant_type=client_credentials";
			postData += "&resource=" + protectedResourceHostName;
			postData += "&client_id=" + appPrincipalId;
			postData += "&client_secret=" + URLEncoder.encode(password, "UTF-8");

			conn.setRequestMethod("POST");
			conn.setDoOutput(true);			
			OutputStreamWriter osw = new OutputStreamWriter(conn.getOutputStream());
			System.out.println("postData ->" + postData);
			osw.write( postData);
			osw.flush();
			osw.close();
			
			BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));			
			String line = ""; 
			StringBuffer stringBuffer = new StringBuffer();
			while((line = br.readLine()) != null){
			stringBuffer.append(line);
			}	
			
			br.close();
			
			logger.info("goodRespStr -> " + stringBuffer.toString());
			accessToken = (new JSONObject(stringBuffer.toString())).optString("access_token");		
			System.out.println("accessToken ->" +  String.format("%s%s", JWTTokenHelper.bearerTokenPrefix, accessToken));
			return String.format("%s%s", JWTTokenHelper.bearerTokenPrefix, accessToken);
			
		
		} catch (MalformedURLException e) {
			throw new SdkException(SdkConfig.ErrorGeneratingToken, SdkConfig.ErrorGeneratingTokenMessage, e);
		} catch (IOException e) {
			String badRespStr = null;
			try {
				badRespStr = HttpClientHelper.getResponseStringFromConn(conn, false);
			} catch (IOException e1) {
				throw new SdkException(SdkConfig.ErrorGeneratingToken, SdkConfig.ErrorGeneratingTokenMessage, e);
			}
			logger.info("badRespStr ->" + badRespStr);
			return badRespStr;
		} catch (JSONException e) {
			throw new SdkException(SdkConfig.ErrorGeneratingToken, SdkConfig.ErrorGeneratingTokenMessage, e);
		} 
	
	}



}
