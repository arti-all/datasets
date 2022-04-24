// Copyright 2014 Connectifier, Inc. All Rights Reserved.

package org.jenkinsci.plugins.saml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

public class SamlRequestGenerator {

  static {
    try {
      DefaultBootstrap.bootstrap();
    } catch (ConfigurationException e) {
      throw new IllegalStateException(e);
    }
  }

  public String createRequestUrl(String ipdBaseUrl, String consumerServiceUrl, String requestIssuer) {
    AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
    AuthnRequest authnRequest = authRequestBuilder.buildObject(SAMLConstants.SAML20P_NS, "AuthnRequest", "samlp");
    authnRequest.setIsPassive(false);
    authnRequest.setIssueInstant(new DateTime());
    authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
    authnRequest.setAssertionConsumerServiceURL(consumerServiceUrl);
    authnRequest.setID(new BigInteger(130, new SecureRandom()).toString(42));
    authnRequest.setVersion(SAMLVersion.VERSION_20);

    IssuerBuilder issuerBuilder = new IssuerBuilder();
    Issuer issuer = issuerBuilder.buildObject(SAMLConstants.SAML20_NS, "Issuer", "samlp" );
    issuer.setValue(requestIssuer);
    authnRequest.setIssuer(issuer);

    NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
    NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
    nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
    nameIdPolicy.setAllowCreate(true);
    authnRequest.setNameIDPolicy(nameIdPolicy);

    RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
    RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
 
    AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
    AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject(SAMLConstants.SAML20_NS, "AuthnContextClassRef", "saml");
    authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

    requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
    authnRequest.setRequestedAuthnContext(requestedAuthnContext);

    Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authnRequest);
    Element authDOM;
    try {
      authDOM = marshaller.marshall(authnRequest);
    } catch (MarshallingException e) {
      throw new IllegalArgumentException(e);
    }
    StringWriter requestWriter = new StringWriter();
    XMLHelper.writeNode(authDOM, requestWriter);
    String messageXML = requestWriter.toString();

    Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
    try {
      deflaterOutputStream.write(messageXML.getBytes());
      deflaterOutputStream.close();
      byteArrayOutputStream.close();
      String base64SamlRequest = new String(new Base64().encode(byteArrayOutputStream.toByteArray())).trim();

      return ipdBaseUrl + "?SAMLRequest=" + URLEncoder.encode(base64SamlRequest, "UTF-8");
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

}
