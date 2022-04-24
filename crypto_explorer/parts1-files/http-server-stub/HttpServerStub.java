package com.lateralthoughts.stub;

import com.google.common.base.Function;
import com.google.common.base.Optional;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.util.concurrent.AbstractService;
import com.google.common.util.concurrent.Service;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.core.Container;
import org.simpleframework.transport.connect.SocketConnection;

import javax.annotation.Nullable;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.common.base.Optional.fromNullable;
import static com.google.common.collect.Collections2.transform;
import static com.google.common.collect.FluentIterable.from;
import static com.google.common.collect.Iterables.tryFind;
import static com.google.common.collect.Lists.newArrayList;
import static com.google.common.collect.Maps.filterKeys;
import static com.google.common.collect.Sets.newLinkedHashSet;


public class HttpServerStub extends AbstractService implements Container {
    private static Log LOG = LogFactory.getLog(HttpServerStub.class);
    public static String KEYSTORE_PROPERTY = "javax.net.ssl.keyStore";
    public static String KEYSTORE_PASSWORD_PROPERTY = "javax.net.ssl.keyStorePassword";
    public static String KEYSTORE_TYPE_PROPERTY = "javax.net.ssl.keyStoreType";

    private Integer port;
    private SocketConnection socketConnection;
    private List<Rule> rules;
    private Map<String, AtomicInteger> counts;
    private boolean ssl;

    public HttpServerStub(Integer port, boolean ssl) {
        this.port = port;
        this.ssl = ssl;
        this.counts = new HashMap<String, AtomicInteger>();
    }

    public static EasyHttpServerStub startServer(boolean ssl) throws TimeoutException {
        return EasyHttpServerStub.createAndStart("rules.properties", ssl);
    }

    public static EasyHttpServerStub startServer(List<Rule> rules, boolean ssl) throws TimeoutException {
        return EasyHttpServerStub.createAndStart(rules, ssl);
    }

    public static EasyHttpServerStub startServer(String rulesFile, boolean ssl) throws TimeoutException {
        return EasyHttpServerStub.createAndStart(rulesFile, ssl);
    }

    public HttpServerStub(Integer port, String rulesFile, boolean ssl) {
        this(port, ssl);
        loadRules(rulesFile);
    }

    public static void main(String[] args) {
        new HttpServerStub(8086, false).loadRules(args[0]).startAsync();
    }

    public void resetCount(String ruleName) {
        this.counts.remove(ruleName);
        this.counts.put(ruleName, new AtomicInteger(0));
    }

    public int count(String ruleName) {
        return fromNullable(this.counts.get(ruleName)).or(new AtomicInteger(0)).get();
    }

    HttpServerStub loadRules(String arg) {
        Properties ruleFile = load(new File(arg));
        Set<String> ruleNames = extractNames(ruleFile);
        return this.rules(newArrayList(transform(ruleNames, toRule(ruleFile))));
    }

    private void initCounts(Set<String> ruleNames) {
        for(String name : ruleNames) {
            this.counts.put(name, new AtomicInteger(0));
        }
    }

    private Function<String, Rule> toRule(final Properties ruleFile) {
        return new Function<String, Rule>() {
            @Override
            public Rule apply(@Nullable String ruleName) {
                return createRule(ruleName, ruleFile);
            }
        };
    }

    private Rule createRule(@Nullable final String ruleName, final Properties ruleFile) {
        if (ruleName == null) return null;
        else return new Rule() {
            @Override
            public boolean accept(final Request req) {
                return allParametersArePresent(req) && urlIsTheRight(req) && allFormParamArePresent(req);
            }

            private boolean urlIsTheRight(Request req) {
                String trimedPath = trimSlashes(req.getPath().getPath());
                String mandatoryTrimedPath = trimSlashes(ruleFile.getProperty(ruleName + ".accept.request.path", trimedPath));
                return trimedPath.equals(mandatoryTrimedPath);
            }

            private boolean allParametersArePresent(Request req) {
                Map<String, String> mandatoryParameters = parametersStartingWith(ruleName + ".accept.request.parameter.", ruleFile);
                return Iterables.all(mandatoryParameters.entrySet(), containsNeedParameter(req));
            }

            private boolean allFormParamArePresent(Request req) {
                Map<String, String> mandatoryParameters = parametersStartingWith(ruleName + ".accept.request.form.", ruleFile);
                return Iterables.all(mandatoryParameters.entrySet(), containsNeedFormParam(req));
            }

            @Override
            public void handle(Request req, Response resp) {
                increment(ruleName);
                resp.setCode(Integer.valueOf(ruleFile.getProperty(ruleName + ".response.code", "200")));
                resp.add("content-type", ruleFile.getProperty(ruleName + ".response.add.content-type", "text/html"));
                try {
                    resp.getOutputStream().write(ruleFile.getProperty(ruleName + ".response.outputStream", "").getBytes());
                } catch (IOException e) {
                    LOG.warn("Warning", e);
                }
            }

            public String name() {
                return ruleName;
            }

            public String toString() {
                return ruleName + " - returns : " + ruleFile.getProperty(ruleName + ".response.outputStream");
            }
        };
    }

    private void increment(String ruleName) {
        this.counts.get(ruleName).incrementAndGet();
    }

    private Predicate<Map.Entry<String, String>> containsNeedParameter(final Request req) {
        return new Predicate<Map.Entry<String, String>>() {
            @Override
            public boolean apply(Map.Entry<String, String> paramNeed) {
                try {
                    return paramNeed.getValue().equalsIgnoreCase(req.getParameter(extractHttpKey(paramNeed.getKey())));
                } catch (IOException e) {
                    LOG.warn("Warning", e);
                    return false;
                }
            }
        };
    }

    private Predicate<Map.Entry<String, String>> containsNeedFormParam(final Request req) {
        return new Predicate<Map.Entry<String, String>>() {
            @Override
            public boolean apply(Map.Entry<String, String> paramNeed) {
                try {
                    return paramNeed.getValue().equalsIgnoreCase(req.getForm().get(extractHttpKey(paramNeed.getKey())));
                } catch (IOException e) {
                    LOG.warn("Warning", e);
                    return false;
                }
            }
        };
    }

    private String extractHttpKey(String key) {
        String sep = ".accept.request.parameter.";
        return key.substring(key.indexOf(sep) + sep.length(), key.length());
    }

    private Map<String, String> parametersStartingWith(final String starts, final Properties ruleFile) {
        return filterKeys(Maps.fromProperties(ruleFile), parametersStartingWith(starts));
    }

    private Predicate<String> parametersStartingWith(final String starts) {
        return new Predicate<String>() {
            @Override
            public boolean apply(@Nullable String propertyName) {
                return propertyName != null && propertyName.startsWith(starts);
            }
        };
    }

    private LinkedHashSet<String> extractNames(Properties ruleFile) {
        return newLinkedHashSet(transform(ruleFile.stringPropertyNames(), new Function<String, String>() {
            @Override
            public String apply(@Nullable String o) {
                return o.substring(0, o.indexOf("."));
            }
        }));
    }

    @Override
    public void handle(Request req, Response resp) {
        try {
            Optional<Rule> rule = firstRuleFor(req);
            if (!rule.isPresent()) {
                LOG.error("No rule found for : " + req);
            } else {
                rule.get().handle(req, resp);
            }
        } finally {
            closeResource(resp);
        }
    }

    private Optional<Rule> firstRuleFor(final Request req) {
        return tryFind(rules, new Predicate<Rule>() {
            @Override
            public boolean apply(@Nullable Rule rule) {
                return rule != null && rule.accept(req);
            }
        });
    }

    @Override
    protected void doStart() {
        try {
            socketConnection = new SocketConnection(this);
            if(!ssl) {
                socketConnection.connect(new InetSocketAddress(port));
            } else {
                socketConnection.connect(new InetSocketAddress(port), sslContext());
            }

            notifyStarted();
            LOG.info("Server started on port : " + port);
            logDocumentation();
        } catch (Exception e) {
            notifyFailed(e);
            LOG.error("Unable to start the server", e);
        }
    }

    public void pause() {
        try {
            socketConnection.close();
        } catch (IOException e) {
            notifyFailed(e);
        } finally {
            LOG.info("Server paused");
        }
    }

    public void unpause() {
        try {
            socketConnection = new SocketConnection(this);
            if(!ssl) {
                socketConnection.connect(new InetSocketAddress(port));
            } else {
                socketConnection.connect(new InetSocketAddress(port), sslContext());
            }

        } catch (Exception e) {
            notifyFailed(e);
        } finally {
            LOG.info("Server paused");
        }
    }

    private SSLContext sslContext() throws Exception {
        String keyStoreFile = System.getProperty(KEYSTORE_PROPERTY, "keystore");
        String keyStorePassword = System.getProperty(KEYSTORE_PASSWORD_PROPERTY,"hopwork1234");
        String keyStoreType = System.getProperty(KEYSTORE_TYPE_PROPERTY, KeyStore.getDefaultType());

        KeyStore keyStore = KeyStore.getInstance(keyStoreType);
        InputStream keyStoreFileInpuStream = null;
        try {
            keyStoreFileInpuStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(keyStoreFile);

            keyStore.load(keyStoreFileInpuStream, keyStorePassword.toCharArray());
        } finally {
            if (keyStoreFileInpuStream != null) {
                keyStoreFileInpuStream.close();
            }
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());

        SSLContext sslContext = SSLContext.getInstance("SSLv3");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        return sslContext;
    }

    @Override
    protected void doStop() {
        try {
            socketConnection.close();
            notifyStopped();
        } catch (IOException e) {
            notifyFailed(e);
        } finally {
            LOG.info("Server stopped");
        }
    }

    public static Properties load(File propsFile) {
        Properties props = new Properties();
        try {
            FileInputStream fis = new FileInputStream(propsFile);
            props.load(fis);
            fis.close();
        } catch (IOException e) {
            LOG.warn("Unable to load rules from file : " + propsFile);
        }
        return props;
    }

    private void closeResource(Response resp) {
        try {
            resp.close();
        } catch (IOException e) {
            LOG.error("Error", e);
        }
    }

    private void logDocumentation() {
        if(rules != null) {
            LOG.info("Rules are apply in this order : " + port);
            for (Rule rule : rules) {
                LOG.info(rule);
            }
        }
    }

    public static String trimSlashes(String string) {
        return string.replaceAll("(^/)|(/$)", "");
    }

    public void clearCounts() {
        for(Rule rule : this.rules) {
            resetCount(rule.name());
        }
    }

    public Callable<Boolean> serverCallCountIs(final int expected) {
        return new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {
                return count("ok") == expected;
            }
        };
    }

    public HttpServerStub rules(List<Rule> rules) {
        this.rules = rules;
        initCounts(from(rules).transform(toName()).toSet());
        return this;
    }

    private Function<? super Rule, String> toName() {
        return new Function<Rule, String>() {
            @Nullable
            @Override
            public String apply(Rule input) {
                return input.name();
            }
        };
    }

    public Integer getPort() {
        return port;
    }

    public State startAndWait() throws TimeoutException {
        Service service = startAsync();
        service.awaitRunning(19l, TimeUnit.SECONDS);
        return service.state();
    }

    public State stopAndWait() throws TimeoutException {
        Service service = stopAsync();
        service.awaitTerminated(19l, TimeUnit.SECONDS);
        return service.state();
    }
}