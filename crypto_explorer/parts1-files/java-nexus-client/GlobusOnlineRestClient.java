package org.globusonline.nexus;
/*
Copyright 2012 Johns Hopkins University Institute for Computational Medicine
Based upon the GlobusOnline Nexus Client written in Python by Mattias Lidman  
available at https://github.com/globusonline/python-nexus-client

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**
* @author Chris Jurado
* 
*/
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Timestamp;


import java.util.*;

import org.globusonline.nexus.exception.NexusClientException;
import org.json.Cookie;
import org.json.JSONException;
import org.json.JSONObject;

public class GlobusOnlineRestClient extends BaseNexusRestClient {
	
	String GO_HOST;
	String oauthSecret;
	Cookie[] sessionCookies;
	
	public GlobusOnlineRestClient() throws NexusClientException{
		testInit();
		init("", "", "");
	}
	
	private void testInit(){
		Properties props = new Properties();
		
	     try {
	            String fileName = "/resources/nexus.config";            
	            InputStream stream = GlobusOnlineRestClient.class.getResourceAsStream(fileName);

	            props.load(stream);

	            GO_HOST = (props.getProperty("globus.url", "missing"));
	            community = (props.getProperty("globus.default.community", "missing"));
	            
	    		if(GO_HOST.equals("missing")){
	    			logger.error("Host URL Configuration missing.");
	    			System.out.println("Missing config item");
	    			return;
	    		}
	            
	        } catch (FileNotFoundException e) {
	        	logger.error("authenticator.config not found.");
	            e.printStackTrace();
	        } catch (IOException e) {
	            e.printStackTrace();
	        }
	}


    public void init(String username, String password, String oauthSecret) throws NexusClientException{
//      Initial login supported either using username+password or
//      username+oauth_secret. The client also supports unauthenticated calls.
    	
        if(!GO_HOST.startsWith("http")){
//		Default to https
        	GO_HOST = "https://" + GO_HOST;
        }
        this.oauthSecret = oauthSecret;
        this.sessionCookies = null;
        this.setCurrentUser(null);
        if(!username.isEmpty()){
            if(!oauthSecret.isEmpty()){
                usernameOauthSecretLogin(username, oauthSecret);
            }
            else {
            	usernamePasswordLogin(username, password);
            }
        }
    }
    
	
    
//    # GROUP OPERATIONS
	
	
	
//    # GROUP MEMBERSHIP OPERATIONS
	
	
	
//    # USER OPERATIONS
	
	public JSONObject usernamePasswordLogin(String username, String password)
			throws NexusClientException {
//        # After successful username/password authentication the user's OAuth secret
//        # is retrieved and used in all subsequent calls until the user is logged out.
//        # If no username is provided, authentication will be attempted using the default
//        # password used by the simple_create_user() method.
        
    	String path = "/authenticate";
    	JSONObject params = new JSONObject();
    	JSONObject content;
    	
        if(password.isEmpty() || password == null){
        	logger.error("Password missing.");
        	return null;
        }  
        
        try{
        	params.put("username", username);
        	params.put("password", password);
        	content = issueRestRequest(path, "POST", "", "", params);
        	
        } catch (JSONException e){
        	logger.error("JSON Exception.");
        	e.printStackTrace();
        	return null;
        }

//        # Also get user secret so that subsequent calls can be made using OAuth:
        
//        JSONObject secretContent = getUserSecret(username, true);
//
//        try {
//			oauthSecret = secretContent.getString("secret");
//		} catch (JSONException e) {
//			logger.error("JSON Exception.");
//			e.printStackTrace();
//		}
//        
//        currentUser = getUser(username);
//        sessionCookies = null;
        
        return content;
    }
    
    public JSONObject usernameOauthSecretLogin(String username, String oauthSecret) throws NexusClientException{
//        # login_username_oauth_secret() tries to retrieve username's user object
//        # using the provided oauth_secret. If succesful, the username and 
//        # oauth_secret will be used for all subsequent calls until user is logged
//        # out. The result of the get_user() call is returned.
    	
    	JSONObject content = getUser(username);
    	
        this.oauthSecret = oauthSecret;
        setCurrentUser(content);

        return content;
    }
    
    public JSONObject logout() throws NexusClientException{
    	
        JSONObject content = issueRestRequest("/logout");
        setCurrentUser(null);
        sessionCookies = null;
        oauthSecret = null;
        return content;
    }
    
    
    
//    # UTILITY FUNCTIONS

    JSONObject getAuthHeaders(String method, String url){
    	
    	JSONObject oauthParams = new JSONObject();
    	JSONObject authHeaders = new JSONObject();
    	Date date = new Date();
    	Timestamp time = new Timestamp(date.getTime());
    	
    	try {
			oauthParams.put("oauth_version", "1.0");
	    	oauthParams.put("oauth_nonce", generateNonce());
	    	oauthParams.put("oauth_timestamp", Integer.valueOf(time.toString()));
		} catch (JSONException e) {
			logger.error("JSON Exception.");
			e.printStackTrace();
		}

//        OAuthRequest oauthRequest = new OAuthRequest(method, url, oauthParams);
//        JSONObject consumer = Consumer(currentUser, oauthSecret);
//        oauthRequest.sign_request(SignatureMethod_HMAC_SHA1(), consumer, null);
//        auth_headers = oauthRequest.to_header();
//        auth_headers = auth_headers['Authorization'].encode('utf-8');
        
        return authHeaders;
    }
    
    private long generateNonce(){
    	SecureRandom sr = null;
		try {
			sr = SecureRandom.getInstance("SHA1PRNG");
	    	byte[] bytes = new byte[1024/8];
	        sr.nextBytes(bytes);
	        int seedByteCount = 10;
	        byte[] seed = sr.generateSeed(seedByteCount);
	        sr = SecureRandom.getInstance("SHA1PRNG");
	        sr.setSeed(seed);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

    	return sr.nextLong();
    }
}
