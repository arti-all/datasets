package com.tagmycode.sdk.authentication;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.extractors.JsonTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;

import java.math.BigInteger;
import java.security.SecureRandom;

public abstract class TagMyCodeApi extends DefaultApi20 {

    public abstract String getDomain();

    public String getEndpointUrl() {
        return "https://api." + getDomain();
    }

    public String getOauthBaseUrl() {
        return "https://" + getDomain();
    }

    public boolean isSsl() {
        return true;
    }

    @Override
    public String getAccessTokenEndpoint() {
        return getOauthBaseUrl() + "/oauth2/token";
    }

    @Override
    public String getAuthorizationUrl(OAuthConfig config) {
        String state = new BigInteger(130, new SecureRandom()).toString(32);

        String authorizeUrl = getOauthBaseUrl() + "/oauth2/authorize?client_id=%s&response_type=code&state=" + state;
        return String.format(authorizeUrl, config.getApiKey());
    }

    public Verb getAccessTokenVerb() {
        return Verb.POST;
    }

    @Override
    public OAuthService createService(OAuthConfig config) {
        return new TagMyCodeServiceImpl(this, config);
    }

    @Override
    public AccessTokenExtractor getAccessTokenExtractor() {
        return new JsonTokenExtractor();
    }

}
