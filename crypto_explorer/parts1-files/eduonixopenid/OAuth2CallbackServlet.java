package eduonix.server.security;

import javax.net.ssl.*;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLDecoder;

/**
 * Created by user on 6/19/15.
 */
public class OAuth2CallbackServlet  extends HttpServlet {


    /**
     *
     *
     * With out this code willget ssl handshake exception shown below
     *
     *
     * javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException:
     * PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException:
     * unable to find valid certification path to requested target
     *
     * @param config
     * @throws ServletException
     */

    @Override
    public void init(ServletConfig config) throws ServletException {

        // All the code below is to overcome host name verification failure we get in certificate
        // validation due to self-signed certificate. This code should not be used in a production
        // setup.

        try {

            SSLContext sc;

            // Get SSL context
            sc = SSLContext.getInstance("SSL");

            // Create empty HostnameVerifier
            HostnameVerifier hv = new HostnameVerifier() {
                public boolean verify(String urlHostName, SSLSession session) {
                    return true;
                }
            };

            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
                                               String authType) {
                }

                public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
                                               String authType) {
                }
            } };

            sc.init(null, trustAllCerts, new java.security.SecureRandom());

            SSLContext.setDefault(sc);
            HttpsURLConnection.setDefaultHostnameVerifier(hv);

        } catch (Exception e) {
            throw new ServletException(e);
        }
    }


    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse resp) throws ServletException, IOException {

        System.out.println("authorise 2 " + URLDecoder.decode(request.getRequestURI(), "UTF-8")   );

        String code = (String) request.getParameter(SecureUtils.CODE);
        String key =  SecureUtils.CONSUMER_KEY_VALUE;
        String secret =  SecureUtils.CONSUMER_SECRET_VALUE;

        HttpSession session = request.getSession();
        System.out.println("code "+code+" key "+key+" secret "+secret);
        session.setAttribute(SecureUtils.CONSUMER_KEY, key);
        session.setAttribute(SecureUtils.CONSUMER_SECRET, secret);
        session.setAttribute(SecureUtils.OAUTH2_ACCESS_ENDPOINT, SecureUtils.REQ_TOK_ENDPOINT);
        session.setAttribute(SecureUtils.CODE, code);
        session.setAttribute(SecureUtils.OAUTH_CALLBACK, SecureUtils.OAUTH_CALLBACK_VALUE);
        resp.sendRedirect("/edusecure/oauth2-token-calls.jsp");
    }




}
