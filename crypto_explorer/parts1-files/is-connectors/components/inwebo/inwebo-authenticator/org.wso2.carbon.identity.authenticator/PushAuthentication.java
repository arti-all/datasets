/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.InputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.File;
import java.io.UnsupportedEncodingException;

import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.SecureRandom;


public class PushAuthentication {
    private static final Log log = LogFactory.getLog(PushAuthentication.class);

    private static String urlString = InweboConstants.INWEBOURL;
    private String serviceId;
    private String p12file;
    private String p12password;
    SSLContext context = null;

    public PushAuthentication(String id, String p12file, String p12password) {
        this.serviceId = id;
        this.p12file = p12file;
        this.p12password = p12password;
    }

    /**
     * Set the client certificate to Default SSL Context
     *
     * @param certificateFile File containing certificate (PKCS12 format)
     * @param certPassword    Password of certificate
     * @throws Exception
     */
    public static SSLContext setHttpsClientCert(String certificateFile, String certPassword)
            throws Exception {
        if (certificateFile == null || !new File(certificateFile).exists()) {
            return null;
        }
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(InweboConstants.SUNFORMAT);
        KeyStore keyStore = KeyStore.getInstance(InweboConstants.PKCSFORMAT);

        InputStream keyInput = new FileInputStream(certificateFile);
        keyStore.load(keyInput, certPassword.toCharArray());

        keyInput.close();
        keyManagerFactory.init(keyStore, certPassword.toCharArray());

        SSLContext context = SSLContext.getInstance(InweboConstants.TLSFORMAT);
        context.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());
        SSLContext.setDefault(context);
        return context;
    }

    /**
     * Prompt for a login and an OTP.
     */
    public JSONObject pushAuthenticate(String userId) throws AuthenticationFailedException {
        String urlParameters = null;
        JSONObject json = null;
        HttpsURLConnection conn = null;
        InputStream is = null;
        try {
            urlParameters = "action=pushAuthenticate"
                    + "&serviceId=" + URLEncoder.encode("" + serviceId, InweboConstants.ENCODING)
                    + "&userId=" + URLEncoder.encode(userId, InweboConstants.ENCODING)
                    + "&format=json";
            if (this.context == null) {
                this.context = setHttpsClientCert(this.p12file, this.p12password);
            }
            SSLSocketFactory sslsocketfactory = context.getSocketFactory();
            URL url = new URL(urlString + urlParameters);
            conn = (HttpsURLConnection) url.openConnection();
            conn.setSSLSocketFactory(sslsocketfactory);
            conn.setRequestMethod("GET");
            is = conn.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(is, InweboConstants.ENCODING));
            JSONParser parser = new JSONParser();
            json = (JSONObject) parser.parse(br);

        } catch (UnsupportedEncodingException e) {
            throw new AuthenticationFailedException("Error while encoding the URL" + e.getMessage(), e);
        } catch (MalformedURLException e) {
            throw new AuthenticationFailedException("Error while creating the URL" + e.getMessage(), e);
        } catch (ParseException e) {
            throw new AuthenticationFailedException("Error while parsing the json object" + e.getMessage(), e);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error while pushing authentication" + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
            try {
                if (is != null) {
                    is.close();
                }
            } catch (IOException e) {
                throw new AuthenticationFailedException("Error while closing stream" + e.getMessage(), e);
            }
        }
        return json;
    }
}
