/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein is strictly forbidden, unless permitted by WSO2 in accordance with
 * the WSO2 Commercial License available at http://wso2.com/licenses. For specific
 * language governing the permissions and limitations under this license,
 * please see the license as well as any agreement you’ve entered into with
 * WSO2 governing the purchase of this software and any associated services.
 */

package org.sample.custom;

import com.google.gdata.util.common.base.Charsets;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sample.custom.internal.OAuthCallbackExtensionComponent;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth.util.UserClaims;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authcontext.ClaimsRetriever;
import org.wso2.carbon.identity.oauth2.authcontext.JWTTokenGenerator;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class CustomJWTTokenGenerator extends JWTTokenGenerator {

    private static final Log log = LogFactory.getLog(CustomJWTTokenGenerator.class);

    private static final String API_GATEWAY_ID = "http://wso2.org/gateway";

    private static final org.apache.commons.codec.binary.Base64 base64Url = new org.apache.commons.codec.binary.Base64();

    private static volatile long ttl = -1L;

    private ClaimsRetriever claimsRetriever;

    private JWSAlgorithm signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.RS256.getName());


    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<Integer, Key>();
    private static Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();

    private ClaimCache claimsLocalCache;

    public CustomJWTTokenGenerator() {
        claimsLocalCache = ClaimCache.getInstance();
    }

    private String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

    String clientId="";


    /**
     * Method that generates the JWT.
     *
     * @return signed JWT token
     * @throws IdentityOAuth2Exception
     */
    @Override
    public void generateToken(OAuth2TokenValidationMessageContext messageContext) throws IdentityOAuth2Exception {

        clientId = ((AccessTokenDO)messageContext.getProperty("AccessTokenDO")).getConsumerKey();
        long issuedTime = ((AccessTokenDO)messageContext.getProperty("AccessTokenDO")).getIssuedTime().getTime();
        String authzUser = messageContext.getResponseDTO().getAuthorizedUser();
        int tenantID = ((AccessTokenDO)messageContext.getProperty("AccessTokenDO")).getTenantID();
        String tenantDomain = OAuth2Util.getTenantDomain(tenantID);
        boolean isExistingUser = false;

        RealmService realmService = OAuthCallbackExtensionComponent.getRealmService();
        // TODO : Need to handle situation where federated user name is similar to a one we have in our user store
        if (realmService != null && tenantID != MultitenantConstants.INVALID_TENANT_ID ) {
            try {
                UserRealm userRealm = realmService.getTenantUserRealm(tenantID);
                if (userRealm != null) {
                    UserStoreManager userStoreManager = (UserStoreManager) userRealm.getUserStoreManager();
                    isExistingUser = userStoreManager.isExistingUser(MultitenantUtils.getTenantAwareUsername
                            (authzUser));
                }
            } catch (UserStoreException e) {
                log.error("Error occurred while loading the realm service", e);
            }
        }

        OAuthAppDAO appDAO =  new OAuthAppDAO();
        OAuthAppDO appDO;
        try {
            appDO = appDAO.getAppInformation(clientId);
            // Adding the OAuthAppDO as a context property for further use
            messageContext.addProperty("OAuthAppDO", appDO);
        } catch (IdentityOAuth2Exception e) {
            log.debug(e.getMessage(), e);
            throw new IdentityOAuth2Exception(e.getMessage());
        } catch (InvalidOAuthClientException e) {
            log.debug(e.getMessage(), e);
            throw new IdentityOAuth2Exception(e.getMessage());
        }
        String subscriber = appDO.getUser().toString();
        String applicationName = appDO.getApplicationName();

        //generating expiring timestamp
        long currentTime = Calendar.getInstance().getTimeInMillis();
        long expireIn = currentTime + 1000 * 60 * getTTL();

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setIssuer(API_GATEWAY_ID);
        claimsSet.setSubject(authzUser);
        claimsSet.setIssueTime(new Date(issuedTime));
        claimsSet.setExpirationTime(new Date(expireIn));
        claimsSet.setClaim(API_GATEWAY_ID+"/subscriber",subscriber);
        claimsSet.setClaim(API_GATEWAY_ID+"/applicationname",applicationName);
        claimsSet.setClaim(API_GATEWAY_ID+"/enduser",authzUser);

        if(claimsRetriever != null){

            //check in local cache
            String[] requestedClaims = messageContext.getRequestDTO().getRequiredClaimURIs();
            if(requestedClaims == null && isExistingUser)  {
                // if no claims were requested, return all
                requestedClaims = claimsRetriever.getDefaultClaims(authzUser);
            }

            ClaimCacheKey cacheKey = null;
            UserClaims result = null;

            if(requestedClaims != null) {
                cacheKey = new ClaimCacheKey(authzUser, requestedClaims);
                result = claimsLocalCache.getValueFromCache(cacheKey);
            }

            SortedMap<String,String> claimValues = null;
            if (result != null) {
                claimValues = result.getClaimValues();
            } else if (isExistingUser) {
                claimValues = claimsRetriever.getClaims(authzUser, requestedClaims);
                UserClaims userClaims = new UserClaims(claimValues);
                claimsLocalCache.addToCache(cacheKey, userClaims);
            }

            if(isExistingUser) {
                String claimSeparator = getMultiAttributeSeparator(authzUser, tenantID);
                if (StringUtils.isBlank(claimSeparator)) {
                    userAttributeSeparator = claimSeparator;
                }
            }

            if(claimValues != null) {
                Iterator<String> it = new TreeSet(claimValues.keySet()).iterator();
                while (it.hasNext()) {
                    String claimURI = it.next();
                    String claimVal = claimValues.get(claimURI);
                    List<String> claimList = new ArrayList<String>();
                    if (userAttributeSeparator != null && claimVal.contains(userAttributeSeparator)) {
                        StringTokenizer st = new StringTokenizer(claimVal, userAttributeSeparator);
                        while (st.hasMoreElements()) {
                            String attValue = st.nextElement().toString();
                            if (StringUtils.isNotBlank(attValue)) {
                                claimList.add(attValue);
                            }
                        }
                        claimsSet.setClaim(claimURI, claimList.toArray(new String[claimList.size()]));
                    } else {
                        claimsSet.setClaim(claimURI, claimVal);
                    }
                }
            }
        }

        JWT jwt = null;
        if(!JWSAlgorithm.NONE.equals(signatureAlgorithm)){
            JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
            header.setX509CertThumbprint(new Base64URL(getThumbPrint(tenantDomain, tenantID)));
            jwt = new SignedJWT(header, claimsSet);
            jwt = signJWT((SignedJWT)jwt, tenantDomain, tenantID);
        } else {
            jwt = new PlainJWT(claimsSet);
        }

        if (log.isDebugEnabled()) {
            log.debug("JWT Assertion Value : " + jwt.serialize());
        }
        OAuth2TokenValidationResponseDTO.AuthorizationContextToken token;
        token = messageContext.getResponseDTO().new AuthorizationContextToken("JWT", jwt.serialize());
        messageContext.getResponseDTO().setAuthorizationContextToken(token);
    }

    /**
     * Sign with given RSA Algorithm
     *
     * @param signedJWT
     * @param jwsAlgorithm
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws IdentityOAuth2Exception
     */
    @Override
    protected SignedJWT signJWTWithRSA(SignedJWT signedJWT, JWSAlgorithm jwsAlgorithm, String tenantDomain,
                                       int tenantId)
            throws IdentityOAuth2Exception {
        try {
            Key privateKey = getPrivateKey(tenantDomain, tenantId);
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            signedJWT.sign(signer);
            return signedJWT;
        } catch (JOSEException e) {
            log.error("Error in obtaining tenant's keystore", e);
            throw new IdentityOAuth2Exception("Error in obtaining tenant's keystore", e);
        } catch (Exception e) {
            log.error("Error in obtaining tenant's keystore", e);
            throw new IdentityOAuth2Exception("Error in obtaining tenant's keystore", e);
        }
    }
    /**
     * Generic Signing function
     *
     * @param signedJWT
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected JWT signJWT(SignedJWT signedJWT, String tenantDomain, int tenantId)
            throws IdentityOAuth2Exception {

        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.RS512.equals(signatureAlgorithm)) {
            return signJWTWithRSA(signedJWT, signatureAlgorithm, tenantDomain, tenantId);
        } else if (JWSAlgorithm.HS256.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
                JWSAlgorithm.HS512.equals(signatureAlgorithm)) {
            // return signWithHMAC(payLoad,jwsAlgorithm,tenantDomain,tenantId); implementation
            // need to be done
        } else if (JWSAlgorithm.ES256.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES384.equals(signatureAlgorithm) ||
                JWSAlgorithm.ES512.equals(signatureAlgorithm)) {
            // return signWithEC(payLoad,jwsAlgorithm,tenantDomain,tenantId); implementation
            // need to be done
        }
        log.error("UnSupported Signature Algorithm");
        throw new IdentityOAuth2Exception("UnSupported Signature Algorithm");
    }

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param tenantDomain
     * @param tenantId
     * @throws IdentityOAuth2Exception
     */
    private String getThumbPrint(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        try {

            Certificate certificate = getCertificate(tenantDomain, tenantId);

            // TODO: maintain a hashmap with tenants' pubkey thumbprints after first initialization

            //generate the SHA-1 thumbprint of the certificate
            MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            byte[] der = certificate.getEncoded();
            digestValue.update(der);
            byte[] digestInBytes = digestValue.digest();

            String publicCertThumbprint = hexify(digestInBytes);
            String base64EncodedThumbPrint = new String(base64Url.encode(publicCertThumbprint.getBytes(Charsets.UTF_8)),
                    Charsets.UTF_8);
            return base64EncodedThumbPrint;

        } catch (Exception e) {
            String error = "Error in obtaining certificate for tenant " + tenantDomain;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    private Key getPrivateKey(String tenantDomain, int tenantId) throws IdentityOAuth2Exception {

        if (tenantDomain == null) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        if (tenantId == 0) {
            tenantId = OAuth2Util.getTenantId(tenantDomain);
        }

        Key privateKey = null;

        if (!(privateKeys.containsKey(tenantId))) {
            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
               KeyStoreInfo keyStoreInfo=selectKeyStore(clientId);
               String jksName = "test-com.jks"; //keyStoreInfo.getKeyStoreName();
                // obtain private key
                privateKey = tenantKSM.getPrivateKey(jksName, tenantDomain);

            } else {
                try {
                    privateKey = generatePrivateKeyforSuperTenant(tenantId,clientId);
                } catch (Exception e) {
                    log.error("Error while obtaining private key for super tenant", e);
                }
            }
            if (privateKey != null) {
                privateKeys.put(tenantId, privateKey);
            }
        } else {
            privateKey = privateKeys.get(tenantId);
        }
        return privateKey;
    }

    private Certificate getCertificate(String tenantDomain, int tenantId) throws Exception {

        if (tenantDomain == null) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        if (tenantId == 0) {
            tenantId = OAuth2Util.getTenantId(tenantDomain);
        }

        Certificate publicCert = null;

        if (!(publicCerts.containsKey(tenantId))) {
            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);

            KeyStore keyStore = null;
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                KeyStoreInfo keyStoreInfo=selectKeyStore(clientId);
                String jksName ="test-com.jks";//keyStoreInfo.getKeyStoreName();
                keyStore = tenantKSM.getKeyStore(jksName);
                publicCert = keyStore.getCertificate(tenantDomain);
            } else {
                publicCert = getDefaultPrimaryCertificateForSuperTenant(tenantId,clientId);
            }
            if (publicCert != null) {
                publicCerts.put(tenantId, publicCert);
            }
        } else {
            publicCert = publicCerts.get(tenantId);
        }
        return publicCert;
    }

    /**
     * Helper method to hexify a byte array.
     * TODO:need to verify the logic
     *
     * @param bytes
     * @return  hexadecimal representation
     */
    private String hexify(byte bytes[]) {

        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }

    private long getTTL() {
        if (ttl != -1) {
            return ttl;
        }

        synchronized (JWTTokenGenerator.class) {
            if (ttl != -1) {
                return ttl;
            }
            String ttlValue = OAuthServerConfiguration.getInstance().getAuthorizationContextTTL();
            if (ttlValue != null) {
                ttl = Long.parseLong(ttlValue);
            } else {
                ttl = 15L;
            }
            return ttl;
        }
    }

    private String getMultiAttributeSeparator(String authenticatedUser, int tenantId) {
        String claimSeparator = null;
        String userDomain = IdentityUtil.extractDomainFromName(authenticatedUser);

        try {
            RealmConfiguration realmConfiguration = null;
            RealmService realmService = OAuthCallbackExtensionComponent.getRealmService();

            if (realmService != null && tenantId != MultitenantConstants.INVALID_TENANT_ID) {
                UserStoreManager userStoreManager = (UserStoreManager) realmService.getTenantUserRealm(tenantId)
                        .getUserStoreManager();
                realmConfiguration = userStoreManager.getSecondaryUserStoreManager(userDomain).getRealmConfiguration();
            }

            if (realmConfiguration != null) {
                claimSeparator = realmConfiguration.getUserStoreProperty(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
                if (claimSeparator != null && !claimSeparator.trim().isEmpty()) {
                    return claimSeparator;
                }
            }
        } catch (UserStoreException e) {
            log.error("Error occurred while getting the realm configuration, User store properties might not be " +
                    "returned", e);
        }
        return null;
    }
    /**
     * Method that returns the Keystore information.
     *
     * @return Keystore information
     * your logic selecting keystore by passing client ID goes here.
     */

    private KeyStoreInfo selectKeyStore(String clientID) {
        log.info("calling the service to select the keystore");
        KeyStoreInfo keyStoreInfo=new KeyStoreInfo();
        keyStoreInfo.setKeyStoreName("wso2carbonold.jks");
        keyStoreInfo.setKeyStorePassword("wso2carbonold");
        keyStoreInfo.setKeyStoreAlias("wso2carbonold");
        return keyStoreInfo;
    }
/**
 *
 * Method that returns the X509Certificate.
 * @param tenantId
 * @param clientId
 * @return X509Certificate
 * @throws Exception
 * */
    private X509Certificate getDefaultPrimaryCertificateForSuperTenant(int tenantId,String clientId) throws Exception {
            KeyStoreInfo keyStoreInfo=selectKeyStore(clientId);
            String alias = keyStoreInfo.getKeyStoreAlias();
            String keyStoreName = keyStoreInfo.getKeyStoreName();
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
            return (X509Certificate)tenantKSM.getKeyStore(keyStoreName).getCertificate(alias);
    }
    /**
     *
     * Method that returns the PrivateKey.
     * @param tenantId
     * @param clientId
     * @return PrivateKey
     * @throws Exception
     * */

    private PrivateKey generatePrivateKeyforSuperTenant(int tenantId, String clientId) throws Exception {
        KeyStoreInfo keyStoreInfo=selectKeyStore(clientId);
        String password =keyStoreInfo.getKeyStorePassword();
        String alias = keyStoreInfo.getKeyStoreAlias();
        String keyStoreName= keyStoreInfo.getKeyStoreName();
        KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
        return (PrivateKey) tenantKSM.getKeyStore(keyStoreName).getKey(alias,password.toCharArray());
    }
}
