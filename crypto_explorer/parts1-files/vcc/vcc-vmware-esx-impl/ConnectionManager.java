package net.java.dev.vcc.impl.vmware.esx.vim;

import com.vmware.vim.ManagedObjectReference;
import com.vmware.vim.VimPortType;
import com.vmware.vim.VimService;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import java.net.MalformedURLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ConnectionManager {

    private static final Logger LOGGER = Logger.getLogger(ConnectionManager.class.getName());

    public static VimPortType getConnection(String url) throws MalformedURLException {
        final VimPortType proxy = new VimService(VimService.class.getResource("vimService.wsdl"),
                new QName("urn:vim2Service", "VimService")
        ).getVimPort();
        final BindingProvider bindingProvider = (BindingProvider) proxy;
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url);
        bindingProvider.getRequestContext().put(BindingProvider.SESSION_MAINTAIN_PROPERTY, true);

        // Install the all-trusting trust manager
        // VMware ESX servers typically have a self-signed cert with the correct hostname
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }

                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            }, new java.security.SecureRandom());
            SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
            bindingProvider.getRequestContext()
                    .put("com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory", sslSocketFactory);
            bindingProvider.getRequestContext()
                    .put("com.sun.xml.ws.transport.https.client.SSLSocketFactory", sslSocketFactory);
//            bindingProvider.getRequestContext().put(com.sun.xml.internal.ws.developer.JAXWSProperties.SSL_SOCKET_FACTORY, sslSocketFactory);
//            bindingProvider.getRequestContext().put(com.sun.xml.ws.developer.JAXWSProperties.SSL_SOCKET_FACTORY, sslSocketFactory);
        } catch (Exception e) {
            LOGGER.log(Level.INFO, "Could not install the all-trusting socket factory", e);
        }

        // Install the all-trusting hostname verifier
        // VMware ESX servers typically do not have a cert with the correct hostname
        final HostnameVerifier verifier = new HostnameVerifier() {
            public boolean verify(String s, SSLSession sslSession) {
                System.out.println("verifying " + s);
                return true;
            }
        };
        bindingProvider.getRequestContext()
                .put("com.sun.xml.internal.ws.transport.https.client.hostname.verifier", verifier);
        bindingProvider.getRequestContext().put("com.sun.xml.ws.transport.https.client.hostname.verifier", verifier);
//        bindingProvider.getRequestContext().put(com.sun.xml.internal.ws.developer.JAXWSProperties.HOSTNAME_VERIFIER, verifier);
//        bindingProvider.getRequestContext().put(com.sun.xml.ws.developer.JAXWSProperties.HOSTNAME_VERIFIER, verifier);
        return proxy;
    }

    public static final ManagedObjectReference getServiceInstance() {
        ManagedObjectReference serviceInstance = new ManagedObjectReference();
        serviceInstance.setType("ServiceInstance");
        serviceInstance.setValue("ServiceInstance");
        return serviceInstance;
    }

}