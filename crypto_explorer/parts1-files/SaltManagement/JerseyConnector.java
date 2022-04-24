package service.http;

import com.sun.jersey.api.client.*;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.api.client.filter.HTTPBasicAuthFilter;
import com.sun.jersey.api.client.filter.LoggingFilter;
import com.sun.jersey.client.impl.ClientRequestImpl;
import com.sun.jersey.core.header.OutBoundHeaders;
import org.apache.log4j.Logger;
import org.codehaus.jackson.jaxrs.JacksonJaxbJsonProvider;
import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;
import org.codehaus.jackson.map.annotate.JsonRootName;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;
import utils.JsonHelper;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.ContextResolver;
import javax.ws.rs.ext.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class JerseyConnector implements PaaSConnector {
    private static Logger logger = Logger.getLogger(JerseyConnector.class);

    static {
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {
            public boolean verify(String hostname, javax.net.ssl.SSLSession sslSession) {
                // if (hostname.equals("name.of.my.server")) {
                return true;
                // }
                // return false;
            }
        });

        //trust all certs.
        TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }};

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected Client client = null;

    public JerseyConnector() {
        ClientConfig clientConfig = new DefaultClientConfig();
        Set<Class<?>> classes = clientConfig.getClasses();
        classes.add(JacksonJaxbJsonProvider.class);
        classes.add(PaasObjectMapper.class);
        client = Client.create(clientConfig);
        HTTPBasicAuthFilter httpBasicAuthFilter = new HTTPBasicAuthFilter("admin", "passw0rd");
        client.addFilter(httpBasicAuthFilter);
    }

    @Override
    public <T> PaaSResponse request(PaaSRequest<T> request) {
        WebResource target = client.resource(request.managerUrl()).path(request.path());
        for (Map.Entry<String, List<Object>> entry : request.queryParams().entrySet()) {
            for (Object o : entry.getValue()) {
                target = target.queryParam(entry.getKey(), String.valueOf(o));
            }
        }
        LoggingFilter loggingFilter = new LoggingFilter();

        target.addFilter(loggingFilter);
        MultivaluedMap<String, Object> headers = new OutBoundHeaders();
        for (Map.Entry<String, List<Object>> h : request.headers().entrySet()) {
            for (Object v : h.getValue()) {
                headers.add(h.getKey(), v);
            }
        }
        if (request.entity() != null && request.entity().getContentType() != null && !"application/x-yaml".equals(request.entity().getContentType())) {
            headers.add("Content-Type", request.entity().getContentType());
        } else {
            headers.add("Content-Type", "application/json");
        }
        try {
            ClientResponse response;
            ClientHandler headHandler = target.getHeadHandler();

            logger.debug("Jersey Request URI: " + target.getURI());
            logger.debug("Jersey Request Method: " + request.method().name());
            logger.debug("Jersey Request Heads: " + headers);
            if (request.entity() != null && request.entity().getEntity() != null) {
                logger.debug("Jersey Request Entity: " + JsonHelper.toJson(request.entity().getEntity()));
                response = headHandler.handle(new ClientRequestImpl(target.getURI(), request.method().name(), request
                        .entity().getEntity(), headers));
            } else {
                response = headHandler.handle(new ClientRequestImpl(target.getURI(), request.method().name(), null,
                        headers));
            }

            //handle the exception
//			PaasExceptionFactory.getOpenStackException(response.getStatus(),response);
            logger.debug("Jersey Response: " + response);
            return new JerseyResponse(response);
        } catch (UniformInterfaceException e) {
            throw new PaaSResponseException(e.getResponse().getClientResponseStatus().getReasonPhrase(), e.getResponse()
                    .getStatus());
        }
    }

    @Provider
    public static class PaasObjectMapper implements ContextResolver<ObjectMapper> {
        static ObjectMapper DEFAULT_MAPPER;
        static ObjectMapper WRAPPED_MAPPER;

        static {
            DEFAULT_MAPPER = new ObjectMapper();
            DEFAULT_MAPPER.setSerializationInclusion(Inclusion.NON_NULL);
            DEFAULT_MAPPER.enable(SerializationConfig.Feature.INDENT_OUTPUT);
            DEFAULT_MAPPER.enable(DeserializationConfig.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
            WRAPPED_MAPPER = new ObjectMapper();
            WRAPPED_MAPPER.setSerializationInclusion(Inclusion.NON_NULL);
            WRAPPED_MAPPER.enable(SerializationConfig.Feature.INDENT_OUTPUT);
            WRAPPED_MAPPER.enable(SerializationConfig.Feature.WRAP_ROOT_VALUE);
            WRAPPED_MAPPER.enable(DeserializationConfig.Feature.UNWRAP_ROOT_VALUE);
            WRAPPED_MAPPER.enable(DeserializationConfig.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY);
        }

        @Override
        public ObjectMapper getContext(Class<?> type) {
            JsonRootName annotation = type.getAnnotation(JsonRootName.class);
            return annotation == null ? DEFAULT_MAPPER : WRAPPED_MAPPER;
        }
    }
}
