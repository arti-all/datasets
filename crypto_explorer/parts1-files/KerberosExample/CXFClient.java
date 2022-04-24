package net.tirasa.kerberosexample;

import static org.apache.cxf.transport.http.auth.HttpAuthHeader.AUTH_TYPE_NEGOTIATE;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.login.LoginException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.helpers.IOUtils;
import org.apache.cxf.interceptor.LoggingOutInterceptor;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.jaxrs.security.KerberosAuthOutInterceptor;
import org.apache.cxf.jaxrs.security.KerberosAuthenticationFilter;
import org.apache.cxf.transport.http.HTTPConduit;

public class CXFClient extends Commons {

    private static WebClient wc;

    public static void main(String[] args) throws LoginException, NoSuchAlgorithmException, KeyManagementException,
            IOException {
        setProperties();
        initWebClient();

        WebClient.getConfig(wc).getOutInterceptors().add(createKerberosAuthInterceptor());
        setClientConduit();

        printConduit(WebClient.getConfig(wc).getHttpConduit());

        Response r = wc.post("{\"method\":\"user_find\",\"params\":[[\"\"],{\"all\":\"true\"}],\"id\":0}");

        LOG.debug("Response status {}", r.getStatus());
        LOG.debug("Response header {}", r.getHeaders());
        LOG.debug("Response {}", IOUtils.readStringFromStream((InputStream) r.getEntity()));
    }

    private static void setClientConduit() {
        WebClient.getConfig(wc).getHttpConduit().getAuthorization().setAuthorizationType(AUTH_TYPE_NEGOTIATE);
        WebClient.getConfig(wc).getHttpConduit().getAuthorization().setAuthorization(JAAS_CONF);
        WebClient.getConfig(wc).getHttpConduit().setAuthorization(createAuthPolicy());
        KerberosAuthenticationFilter a = new KerberosAuthenticationFilter();
        a.setLoginContextName(JAAS_CONF);
        a.setRealm("TIRASA.NET");
        a.setServicePrincipalName("ldap/olmo.tirasa.net");
    }

    private static KerberosAuthOutInterceptor createKerberosAuthInterceptor() {
        final KerberosAuthOutInterceptor kbInterceptor = new KerberosAuthOutInterceptor();
        kbInterceptor.setPolicy(createAuthPolicy());
        kbInterceptor.setCredDelegation(true);
//        kbInterceptor.setServicePrincipalName("HTTP/olmo.tirasa.net");
//        kbInterceptor.setRealm("TIRASA.NET");
        return kbInterceptor;
    }

    private static AuthorizationPolicy createAuthPolicy() {
        AuthorizationPolicy policy = new AuthorizationPolicy();
        policy.setAuthorizationType(AUTH_TYPE_NEGOTIATE);
        policy.setAuthorization(JAAS_CONF);
        return policy;
    }

    public static void initWebClient() throws NoSuchAlgorithmException, KeyManagementException {
        wc = WebClient.create("https://olmo.tirasa.net/ipa/json");
        final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

            @Override
            public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
            }

            @Override
            public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        }};

        final SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

        final TLSClientParameters p = new TLSClientParameters();
        p.setDisableCNCheck(true);
        p.setSSLSocketFactory(sslSocketFactory);

        WebClient.getConfig(wc).getHttpConduit().setTlsClientParameters(p);
        WebClient.getConfig(wc).getOutInterceptors().add(new LoggingOutInterceptor());

//        wc.header("referer", "https://olmo.tirasa.net/ipa");
        wc.type(MediaType.APPLICATION_JSON);
        wc.accept(MediaType.APPLICATION_JSON);

        LOG.debug("Web client created successfully");
    }

    private static void printConduit(final HTTPConduit conduit) {
        LOG.debug("Conduit address {}", conduit.getAddress());
        LOG.debug("Conduit base name {}", conduit.getBeanName());
        LOG.debug("Conduit auth type {}", conduit.getAuthorization().getAuthorizationType());
        LOG.debug("Conduit auth {}", conduit.getAuthorization().getAuthorization());
        LOG.debug("Conduit is auth {}", conduit.getAuthorization().isSetAuthorization());
        LOG.debug("Conduit is auth type {}", conduit.getAuthorization().isSetAuthorizationType());
        LOG.debug("Conduit pwd {}", conduit.getAuthorization().isSetPassword());
        LOG.debug("Conduit user {}", conduit.getAuthorization().isSetUserName());
    }
}
