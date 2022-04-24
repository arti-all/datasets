package net.tirasa.kerberosexample;

import static net.tirasa.kerberosexample.Commons.KERB_V5_OID;
import static net.tirasa.kerberosexample.Commons.KRB5_PRINCIPAL_NAME_OID;
import static net.tirasa.kerberosexample.Commons.LOG;
import static net.tirasa.kerberosexample.Commons.setProperties;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.Set;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import org.apache.ws.security.util.Base64;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.MessageProp;
import sun.misc.BASE64Encoder;

public class SecondGSSClient extends Commons {

    public static void main(final String args[]) throws LoginException, NoSuchAlgorithmException, KeyManagementException,
            IOException, PrivilegedActionException {
        setProperties();
        final String ticket = retrieveTicket(SERVICE_PRINCIPAL_NAME);
        LOG.debug("Calling server with ticket {}", ticket);
//        postWithTicket(ticket);
    }

    public static String retrieveTicket(final String applicationPrincipal) throws LoginException,
            PrivilegedActionException, MalformedURLException {
//        final Subject subject = login();
        final Subject subject = kerberosLogin();

        LOG.debug("Authenticated with {}", subject);

        final Set<Principal> principalSet = subject.getPrincipals();
        if (principalSet.size() != 1) {
            LOG.error("No or several principals {}", principalSet);
            throw new AssertionError("No or several principals: " + principalSet);
        }
        final Principal userPrincipal = principalSet.iterator().next();
        LOG.debug("user principale found {}", userPrincipal);

        final GssClientAction action = new SecondGSSClient.GssClientAction(userPrincipal.getName(),
                applicationPrincipal, "olmo.tirasa.net", 88);

        Subject.doAs(subject, action);
        return "";
    }

    static class GssClientAction implements PrivilegedExceptionAction {

        private String userPrincipal;

        private String applicationPrincipal;

        private String hostName;

        private int port;

        GssClientAction(String userPrincipal, String applicationPrincipal, String hostName, int port) {
            this.userPrincipal = userPrincipal;
            this.applicationPrincipal = applicationPrincipal;
            this.hostName = hostName;
            this.port = port;
        }

        public Object run() throws Exception {
            Socket socket = new Socket(hostName, port);
            DataInputStream inStream = new DataInputStream(socket.getInputStream());
            DataOutputStream outStream = new DataOutputStream(socket.getOutputStream());

            System.out.println("Connected to address " + socket.getInetAddress());

            /*
             * This Oid is used to represent the Kerberos version 5 GSS-API
             * mechanism. It is defined in RFC 1964. We will use this Oid
             * whenever we need to indicate to the GSS-API that it must
             * use Kerberos for some purpose.
             */
            final GSSManager manager = GSSManager.getInstance();
            final GSSName clientName = manager.createName(userPrincipal, KRB5_PRINCIPAL_NAME_OID);

            LOG.debug("GSSname client name created {}", clientName);

            final GSSCredential clientCred = manager.createCredential(clientName,
                    8 * 3600,
                    KERB_V5_OID,
                    GSSCredential.INITIATE_ONLY);

            LOG.debug("GSSCredentials created {}", clientCred);

            final GSSName serverName = manager.createName(applicationPrincipal, KRB5_PRINCIPAL_NAME_OID);

            LOG.debug("GSSName server name created {}", serverName);

            final GSSContext context = manager.createContext(serverName,
                    KERB_V5_OID,
                    clientCred,
                    GSSContext.DEFAULT_LIFETIME);

            LOG.debug("GSSContext created {}", context);

            // Set the desired optional features on the context. The client
            // chooses these options.
            context.requestMutualAuth(true);  // Mutual authentication
            context.requestConf(true);  // Will use confidentiality later
            context.requestInteg(true); // Will use integrity later

            // Do the context eastablishment loop
            final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {

                @Override
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
            };

            final SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            final HostnameVerifier allHostsValid = new HostnameVerifier() {

                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };

            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
            URLConnection con = null;
            OutputStream o = null;
            while (!context.isEstablished()) {

                final byte[] token = context.initSecContext(new byte[0], 0, 0);

                try {
                    final URL url = new URL("https://olmo.tirasa.net/ipa/json");

                    LOG.debug("URL set to {}", url);

                    con = url.openConnection();

                    con.setRequestProperty("Authorization", "Negotiate: " + Base64.encode(token));
                    con.setDoOutput(true);
                    con.setDoInput(true);

                    if (token != null) {
                        o = con.getOutputStream();
                        StringBuilder outputBuffer = new StringBuilder();
                        outputBuffer.append(String.format("Src Name: %s\n", context.getSrcName()));
                        outputBuffer.append(String.format("Target  : %s\n", context.getTargName()));
                        outputBuffer.append(new BASE64Encoder().encode(token));
                        outputBuffer.append("\n");
                        o.write(outputBuffer.toString().getBytes());
                        o.flush();
                    }
//                    final Reader reader = new InputStreamReader(con.getInputStream());
//
//                    while (true) {
//                        int ch = reader.read();
//                        if (ch == -1) {
//                            break;
//                        }
//                        LOG.debug("RETURN STATUS {}", (char) ch);
//                    }
                } catch (IOException ioe) {
                    LOG.error("IOE ", ioe);
                }

                // token is ignored on the first call
                // Send a token to the server if one was generated by
                // initSecContext
                if (token != null) {

                    StringBuilder outputBuffer = new StringBuilder();
                    outputBuffer.append(String.format("Src Name: %s\n", context.getSrcName()));
                    outputBuffer.append(String.format("Target  : %s\n", context.getTargName()));
                    outputBuffer.append(new BASE64Encoder().encode(token));
                    outputBuffer.append("\n");
                    o = con.getOutputStream();
                    o.write(outputBuffer.toString().getBytes());
                    o.flush();
                }

                // If the client is done with context establishment
                // then there will be no more tokens to read in this loop
//                if (!context.isEstablished()) {
//                    token = new byte[inStream.readInt()];
//                    inStream.readFully(token);
//                }
            }

            System.out.println("Context Established! ");
            System.out.println("Client principal is " + context.getSrcName());
            System.out.println("Server principal is " + context.getTargName());

            return null;
        }
    }

    private static final String getHexBytes(byte[] bytes, int pos, int len) {

        StringBuffer sb = new StringBuffer();
        for (int i = pos; i < (pos + len); i++) {

            int b1 = (bytes[i] >> 4) & 0x0f;
            int b2 = bytes[i] & 0x0f;

            sb.append(Integer.toHexString(b1));
            sb.append(Integer.toHexString(b2));
            sb.append(' ');
        }
        return sb.toString();
    }

    private static final String getHexBytes(byte[] bytes) {
        return getHexBytes(bytes, 0, bytes.length);
    }
}
