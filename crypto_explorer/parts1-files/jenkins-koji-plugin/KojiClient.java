package org.jenkinsci.plugins.koji.xmlrpc;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.client.XmlRpcClient;
import org.apache.xmlrpc.client.XmlRpcClientConfigImpl;
import org.apache.xmlrpc.client.XmlRpcCommonsTransportFactory;

import javax.net.ssl.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Singleton used for XML-RPC communication with Koji.
 */
public class KojiClient {

    /**
     * Internal XML-RPC client instance not exposed for direct calls. Everything needs to go through KojiClient.
     */
    private XmlRpcClient koji;
    /**
     * Singleton.
     */
    private static KojiClient instance;
    /**
     * Koji hub Instance URL. Must end with "kojihub" suffix or leading to other custom URL pointing directly to koji server XML-RPC hub.
     */
    private String kojiInstanceURL;

    public String getKojiInstanceURL() {
        return kojiInstanceURL;
    }

    private KojiClient(String kojiInstanceURL) throws MalformedURLException {
        this.kojiInstanceURL = kojiInstanceURL;
        this.koji = connect(kojiInstanceURL);
    }

    /**
     * Get the KojiClient Singleton instance. If user changes global config with Koji Hub URL, it's eventually modified here.
     *
     * @param kojiInstanceURL URL of remote Koji instance.
     */
    public static KojiClient getKojiClient(String kojiInstanceURL) throws MalformedURLException {
        if (instance == null)
            instance = new KojiClient(kojiInstanceURL);
        else {
            if (instance.getKojiInstanceURL() != kojiInstanceURL) {
                instance.setServerURL(kojiInstanceURL);
            }
        }

        return instance;
    }

    /**
     * Login to XML-RPC service using plain authentication. This authentication is the only supported via Koji XML-RPC API.
     * @param userName Username
     * @param password Password
     * @return KojiSession.
     * @throws XmlRpcException In case issue with login happens.
     */
    public KojiSession login(String userName, String password) throws XmlRpcException {
        List<Object> params = new ArrayList<Object>();
        params.add(userName);
        params.add(password);

        Map<String, ?> session = null;

        try {
            session = (Map<String, ?>) koji.execute("login", params);
        } catch (XmlRpcException e) {
            throw e;
        }

        KojiSession kojiSession = new KojiSession(kojiInstanceURL, session);

        setServerURL(kojiSession.getAuthenticatedHubURL());

        return kojiSession;
    }
    /**
     * Gets latest builds.
     *
     * @param tag Koji tag
     * @param pkg Koji package
     * @return Map of properties for latest build.
     */
    public Map<String, String> getLatestBuilds(String tag, String pkg) throws XmlRpcException {
        // Koji XML-RPC API
        // getLatestBuilds(tag, event=None, package=None, type=None)
        // description: List latest builds for tag (inheritance enabled)

        List<Object> params = new ArrayList<Object>();
        params.add(tag);
        // Event is of no interest to us.
        params.add(null);
        params.add(pkg);

        Object[] latestBuilds = null;
        Map<String, String> buildInfo = null;
        try {
            latestBuilds = (Object[]) koji.execute("getLatestBuilds", params);
            if (latestBuilds == null) {
                throw new XmlRpcException("empty");
            }
            if (latestBuilds.length == 0) {
                throw new XmlRpcException("empty");
            }
            buildInfo = (Map<String, String>) latestBuilds[0];
        } catch (XmlRpcException e) {
            throw e;
        }

        return buildInfo;
    }

    /**
     * Retrieves information about a given build.
     *
     * @param buildId BuildId can be Name-Version-Release (NVR) or numeric buildId.
     * @return A map containing all information about given build.
     */
    public Map<String, String> getBuildInfo(String buildId) throws XmlRpcException {
     /* XML-RPC method information
        getBuild(buildInfo, strict=False)
        description: Return information about a build.  buildID may be either
        a int ID, a string NVR, or a map containing 'name', 'version'
        and 'release.  A map will be returned containing the following
        keys:
        id: build ID
        package_id: ID of the package built
        package_name: name of the package built
        version
        release
        epoch
        nvr
        state
        task_id: ID of the task that kicked off the build
        owner_id: ID of the user who kicked off the build
        owner_name: name of the user who kicked off the build
        volume_id: ID of the storage volume
        volume_name: name of the storage volume
        creation_event_id: id of the create_event
        creation_time: time the build was created (text)
        creation_ts: time the build was created (epoch)
        completion_time: time the build was completed (may be null)
        completion_ts: time the build was completed (epoch, may be null)

        If there is no build matching the buildInfo given, and strict is specified,
                raise an error.  Otherwise return None. */

        List<Object> params = new ArrayList<Object>();
        params.add(buildId);
        Map<String, String> buildInfo;

        try {
            buildInfo = (Map<String, String>) koji.execute("getBuild", params);
        } catch (XmlRpcException e) {
            throw e;
        }

        if (buildInfo == null) {
            throw new XmlRpcException("empty");
        }

        return buildInfo;

    }

    /**
     * Gets information about logged user.
     *
     * @return Session identification.
     */
    public String getSession() {
        String result = null;
        try {
            result = (String) koji.execute("showSession", new Object[]{});
        } catch (XmlRpcException e) {
            e.printStackTrace();
        }

        return result;
    }

    /**
     * Method for detailed queries.
     * @param buildParams Accepts BuildParams object holding various properties.
     */
    public List<Map<String, String>> listTaggedBuilds(BuildParams buildParams) throws XmlRpcException {
        // Koji XML-RPC API
        // listTagged(tag, event=None, inherit=False, prefix=None, latest=False, package=None, owner=None, type=None)
        // description: List builds tagged with tag

        List<Object> params = new ArrayList<Object>();
        params.add(buildParams.getTag());
        // Event is of no interest to us.
        params.add(null);
        params.add(false);
        params.add(null);
        params.add(buildParams.isLatest());
        params.add(buildParams.getPkg());
        params.add(buildParams.getOwner());
        params.add(buildParams.getType());

        Object[] objects = null;

        try {
            objects = (Object[]) koji.execute("listTagged", params);
        } catch (XmlRpcException e) {
            throw e;
        }

        if (objects == null) {
            throw new XmlRpcException("empty");
        }

        List<Map<String, String>> results = new LinkedList<Map<String, String>>();

        for (Object o : objects) {
            Map<String, String> map = (Map<String, String>) o;
            results.add(map);
        }

        return results;
    }

    /**
     * Greet the remote Koji instance and test the communication.
     *
     * @return
     */
    public String sayHello() {
        StringBuilder sb = new StringBuilder();
        try {
            Object result = koji.execute("hello", new Object[]{"Hello"});
            sb.append("Jenkins-Koji Plugin: Hello Koji server running at " + kojiInstanceURL);
            sb.append("\nKoji: " + result);

            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Connect to remote Koji instance. Uses custom Transport factory adding a None / null support for XML-RPC.
     *
     * @param kojiInstanceURL Address of the remote Koji server.
     * @return XMLRPC client instance.
     */
    private XmlRpcClient connect(String kojiInstanceURL) throws MalformedURLException {
        XmlRpcClient koji = new XmlRpcClient();
        koji.setTransportFactory(new XmlRpcCommonsTransportFactory(koji));
        XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
        koji.setTransportFactory(new XmlRpcCommonsTransportFactory(koji));
        koji.setTypeFactory(new MyTypeFactory(koji));
        config.setEnabledForExtensions(true);
        config.setEnabledForExceptions(true);

        try {
            config.setServerURL(new URL(kojiInstanceURL));
        } catch (MalformedURLException e) {
            throw e;
        }

        koji.setConfig(config);

        return koji;
    }

    public void setServerURL(String kojiInstanceURL) {
        XmlRpcClientConfigImpl config = new XmlRpcClientConfigImpl();
        config.setEnabledForExtensions(true);
        config.setEnabledForExceptions(true);
        try {
            config.setServerURL(new URL(kojiInstanceURL));
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        koji.setConfig(config);
    }

    private void initSSL() {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Trust always
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Trust always
                    }
                }
        };

        // Install the all-trusting trust manager
        SSLContext sc = null;
        try {
            sc = SSLContext.getInstance("SSL");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // Create empty HostnameVerifier
        HostnameVerifier hv = new HostnameVerifier() {
            public boolean verify(String arg0, SSLSession arg1) {
                return true;
            }
        };


        try {
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier(hv);
        SSLContext.setDefault(sc);
    }

    public void setDebug(boolean debug) {
        if (debug)
            koji.setTransportFactory(new MyXmlRpcCommonsTransportFactory(koji));
        else
            koji.setTransportFactory(new XmlRpcCommonsTransportFactory(koji));
    }

    /**
     * Holds Koji Build parameters. Use BuildParamsBuilder for initialization.
     */
    static class BuildParams {
        private final String id;
        private final String tag;
        private final boolean latest;
        private final String pkg;
        private final String owner;
        private final String type;

        BuildParams(String id, String tag, boolean latest, String pkg, String owner, String type) {
            this.id = id;

            this.tag = tag;
            this.latest = latest;
            this.pkg = pkg;
            this.owner = owner;
            this.type = type;
        }

        public String getId() {
            return id;
        }

        public String getTag() {
            return tag;
        }

        public boolean isLatest() {
            return latest;
        }

        public String getPkg() {
            return pkg;
        }

        public String getOwner() {
            return owner;
        }

        public String getType() {
            return type;
        }
    }

    /**
     * Builder instance for BuildParams providing default values.
     */
    static class BuildParamsBuilder {
        private String id = null;
        private String tag = null;
        private boolean latest = false;
        private String pkg = null;
        private String owner = null;
        private String type = null;

        BuildParamsBuilder setId(String id) {
            this.id = id;
            return this;
        }

        BuildParamsBuilder setTag(String tag) {
            this.tag = tag;
            return this;
        }

        BuildParamsBuilder setLatest(boolean latest) {
            this.latest = latest;
            return this;
        }

        BuildParamsBuilder setPackage(String pkg) {
            this.pkg = pkg;
            return this;
        }

        BuildParamsBuilder setOwner(String owner) {
            this.owner = owner;
            return this;
        }

        BuildParamsBuilder setType(String type) {
            this.type = type;
            return this;
        }

        BuildParams build() {
            return new BuildParams(id, tag, latest, pkg, owner, type);
        }
    }
}
