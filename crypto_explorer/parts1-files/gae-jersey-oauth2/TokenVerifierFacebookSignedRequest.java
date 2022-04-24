/*
 * Copyright (c) 2016 Dzmitry Lazerka
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package me.lazerka.gae.jersey.oauth2.facebook;

import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.appengine.api.urlfetch.URLFetchService;
import com.google.common.base.Splitter;
import com.google.common.base.Throwables;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import static com.google.common.base.Preconditions.checkArgument;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Verifies FB signed_request by checking its signature.
 *
 * Documentation on token verification:
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#confirm
 * https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow#checktoken
 *
 * Documentation on parsing signed_request: https://developers.facebook.com/docs/games/gamesonfacebook/login#parsingsr
 *
 * @author Dzmitry Lazerka
 */
public class TokenVerifierFacebookSignedRequest extends BasicTokenVerifier {
	private static final Logger logger = LoggerFactory.getLogger(TokenVerifierFacebookSignedRequest.class);

	public static final String AUTH_SCHEME = "Facebook/SignedRequest";

	private final Mac hmac;

	final ObjectMapper jackson;
	final String redirectUri;
	final FacebookFetcher fetcher;

	public TokenVerifierFacebookSignedRequest(
			URLFetchService urlFetchService,
			ObjectMapper jackson,
			String appId,
			String appSecret,
			String redirectUri
	) {
		this.jackson = jackson;
		this.redirectUri = redirectUri;
		this.fetcher = new FacebookFetcher(appId, appSecret, jackson, urlFetchService);

		try {
			SecretKeySpec signingKey = new SecretKeySpec(appSecret.getBytes(UTF_8), "HmacSHA1");
			hmac = Mac.getInstance("HmacSHA256");
			hmac.init(signingKey);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw Throwables.propagate(e);
		}
	}

	@Override
	public FacebookUserPrincipal verify(String signedRequestToken) throws IOException, InvalidKeyException {
		logger.trace("Requesting endpoint to validate token");

		List<String> parts = Splitter.on('.').splitToList(signedRequestToken);

		checkArgument(parts.size() == 2, "Signed request must have two parts separated by period.");

		byte[] providedSignature = Base64Variants.MODIFIED_FOR_URL.decode(parts.get(0));
		String signedRequestJsonEncoded = parts.get(1);
		byte[] signedRequestJson = Base64Variants.MODIFIED_FOR_URL.decode(signedRequestJsonEncoded);

		SignedRequest signedRequest = jackson.readValue(signedRequestJson, SignedRequest.class);

		if (!"HMAC-SHA256".equals(signedRequest.algorithm)) {
			throw new InvalidKeyException("Unsupported signing method: " + signedRequest.algorithm);
		}

		byte[] expectedSignature = hmac.doFinal(signedRequestJsonEncoded.getBytes(UTF_8));
		if (!Arrays.equals(providedSignature, expectedSignature)) {
			throw new InvalidKeyException("Signature invalid");
		}

		// We still need to verify expiration somehow. The only way is to ask Facebook.

		// Exchange `code` for long-lived access token.
		// This serves as verification for `code` expiration too.

		AccessTokenResponse response = fetcher.fetchUserAccessToken(signedRequest.code, redirectUri);

		// Not fetching email, because maybe we won't need to, if ID is enough.

		return new FacebookUserPrincipal(signedRequest.userId, null, response, null);
	}

	@Override
	public String getAuthenticationScheme() {
		return AUTH_SCHEME;
	}
}
