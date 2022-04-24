/**
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 * <p>
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.dashboard.migratetool;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class DSPortalAppMigrationTool extends DSMigrationTool {
    private static final Log log = LogFactory.getLog(DSPortalAppMigrationTool.class);
    private static final String GADGET = "gadget";
    private static final String WIDGET = "widget";
    private static final String LAYOUT = "layout";
    private static final String BLOCKS = "blocks";
    private static final String INDEX_JSON = "index.json";
    private static String storePath = "/home/nisala/WSO2/TR/wso2ds-2.1.0-SNAPSHOT/repository/deployment/server/jaggeryapps/portal/store";

    public static void main(String arg[]) {
        DSPortalAppMigrationTool dsPortalAppMigrationTool = new DSPortalAppMigrationTool();
        //dsPortalAppMigrationTool.migrateArtifactsInStore();
        dsPortalAppMigrationTool.getDashboard();
    }

    /**
     * migrate the different types of artifacts such as gadgets,widgets and layouts into newer version
     */
    private void migrateArtifactsInStore() {
        File store = new File(storePath);
        File[] tenantStores = store.listFiles();
        for (int i = 0; i < tenantStores.length; i++) {
            if (tenantStores[i].isDirectory()) {
                File[] storeTypes = tenantStores[i].listFiles();
                for (int storeCount = 0; storeCount < storeTypes.length; storeCount++) {
                    if (storeTypes[storeCount].isDirectory()) {
                        File[] artifactTypes = storeTypes[storeCount].listFiles();
                        for (int artifactCount = 0; artifactCount < artifactTypes.length; artifactCount++) {
                            if (artifactTypes[artifactCount].getName().equalsIgnoreCase(GADGET)
                                    || artifactTypes[artifactCount].getName().equalsIgnoreCase(WIDGET)) {
                                new DSPortalAppMigrationTool().gadgetJSONUpdater(artifactTypes[artifactCount]);
                            } else if (artifactTypes[artifactCount].getName().equalsIgnoreCase(LAYOUT)) {
                                migrateLayoutsInStore(artifactTypes[artifactCount]);
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * migrate layouts into newer version
     *
     * @param layouts file path of the layouts directory
     */
    private void migrateLayoutsInStore(File layouts) {
        File[] listOflayouts = layouts.listFiles();
        JSONParser parser = new JSONParser();
        for (int layoutCount = 0; layoutCount < listOflayouts.length; layoutCount++) {
            try {
                JSONObject layoutObj = (JSONObject) parser.parse(new FileReader(
                        listOflayouts[layoutCount].getAbsolutePath() + File.separator + INDEX_JSON));
                updateDashboardBlocks(((JSONArray) layoutObj.get(BLOCKS)));
                FileWriter file = new FileWriter(
                        listOflayouts[layoutCount].getAbsolutePath() + File.separator + INDEX_JSON);
                file.write(layoutObj.toJSONString());
                file.flush();
                file.close();

            } catch (IOException e) {
                log.error("Error in opening the file " + listOflayouts[layoutCount].getName(), e);
            } catch (ParseException e) {
                log.error("Error in parsing the index.json file in " + listOflayouts[layoutCount].getAbsolutePath());
            }
        }
    }

    private TrustManager[] get_trust_mgr() {
        TrustManager[] certs = new TrustManager[] { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String t) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String t) {
            }
        } };
        return certs;
    }

    public void getDashboard() {

        String response = invokeRestAPI("https://localhost:9443/portal/apis/login?username=admin&password=admin",
                "POST", null);
        try {
            JSONObject responseObj = (JSONObject) new JSONParser().parse(response.toString());
            response = invokeRestAPI("https://localhost:9443/portal/apis/dashboards", "GET",
                    (String) responseObj.get("sessionId"));
            JSONArray responseArr = (JSONArray) new JSONParser().parse(response.toString());
            for (int dashboardCount = 0 ; dashboardCount < responseArr.size() ; dashboardCount++) {
               // dashboardUpdater((JSONObject) responseArr[dashboardCount]);
            }
            System.out.println(responseArr.toJSONString());
        } catch (ParseException e) {
            e.printStackTrace();
        }
    }

    public String invokeRestAPI(String requestURL, String requestType, String sessionId) {
        try {
            SSLContext ssl_ctx = SSLContext.getInstance("TLS");
            TrustManager[] trust_mgr = get_trust_mgr();
            ssl_ctx.init(null,                // key manager
                    trust_mgr,           // trust manager
                    new SecureRandom()); // random number generator
            HttpsURLConnection.setDefaultSSLSocketFactory(ssl_ctx.getSocketFactory());

            URL url = new URL(requestURL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod(requestType);
            if (sessionId != null) {
                conn.setRequestProperty("Cookie", "JSESSIONID=" + sessionId);
            }
            conn.setRequestProperty("Accept", "application/json");

            if (conn.getResponseCode() != 200) {
                throw new RuntimeException("Failed : HTTP error code : " + conn.getResponseCode());
            }
            BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
            String output;
            StringBuilder buffer = new StringBuilder();
            System.out.println("Output from Server .... \n");
            while ((output = br.readLine()) != null) {
                System.out.println(output);
                buffer.append(output);
            }
            output = buffer.toString();
            conn.disconnect();
            return output;
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {

        } catch (NoSuchAlgorithmException e) {

        }
        return null;
    }

    /**
     * update dahboard json in the ds dashboard in order to compatible with carbon-dashboards version 1.0.15+
     *
     * @param dashboardJSONObject dashboardJSON to be updated
     */
    private JSONObject dashboardUpdater(JSONObject dashboardJSONObject) {
        Object obj = dashboardJSONObject.get("pages");
        JSONArray pagesJSONArray = (JSONArray) obj;
        for (int pageCount = 0; pageCount < pagesJSONArray.size(); pageCount++) {
            JSONObject pageObj = ((JSONObject) pagesJSONArray.get(pageCount));
            JSONArray blocksArray = ((JSONArray) ((JSONObject) ((JSONObject) ((JSONObject) pageObj.get("layout"))
                    .get("content")).get("loggedIn")).get("blocks"));
            JSONObject gadgetSet = ((JSONObject) ((JSONObject) pageObj.get("content")).get("default"));
            Object[] keySet = ((JSONObject) ((JSONObject) pageObj.get("content")).get("default")).keySet().toArray();
            for (int gadgetCount = 0; gadgetCount < keySet.length; gadgetCount++) {
                dashboardGadgetUpdater(((JSONArray) gadgetSet.get(keySet[gadgetCount])));
            }
            updateDashboardBlocks(blocksArray);
        }
        return dashboardJSONObject;
    }
}
