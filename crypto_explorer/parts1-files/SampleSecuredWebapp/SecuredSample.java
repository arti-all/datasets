package org.wso2.commons.samples;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.log4j.Logger;

import sun.misc.BASE64Encoder;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@WebServlet("/SecuredSample")
public class SecuredSample extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static Logger log = Logger.getLogger(SecuredSample.class);
	private static String serviceURL = "http://localhost:9763/services/samples/JSONSample/";

	@Override
	public void init() throws ServletException {

	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		processRequest(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		processRequest(req, resp);
	}

	private void processRequest(HttpServletRequest req, HttpServletResponse resp)
			throws IOException, ServletException {
		String cmd;
		String salary;
		// simple request processing based on url parameters
		cmd = req.getParameter("cmd");
		if (cmd == null || "get".equals(cmd)) {
			sendGETRequest(req, resp);
			return;
		}

		salary = (String) req.getParameter("sal");
		if (salary == null) {
			salary = "9999";
		}

		if ("update".equals(cmd)) {
			sendPUTRequest(req, resp, salary);
			return;
		}
	}

	/***
	 * Sends a GET request to the endpoint
	 * 
	 * @param req
	 *            - request object
	 * @param resp
	 *            - response object
	 * @throws IOException
	 * @throws ServletException
	 */
	private void sendGETRequest(HttpServletRequest req, HttpServletResponse resp)
			throws IOException, ServletException {
		PrintWriter out = resp.getWriter();
		KeyPair clientKeyPair;
		try {
			clientKeyPair = loadClientKeyPair();
			SignedJWT signedJWT = getSignedJWT(null, clientKeyPair.getPublic(),
					clientKeyPair.getPrivate());
			// create the new url with the token as a URL param
			URL url = new URL(serviceURL + "employee/1002?tok="
					+ signedJWT.serialize());

			URLConnection connection = url.openConnection();
			connection.setRequestProperty("accept", "application/json");
			InputStream in = connection.getInputStream();

			String result = readPayload(in);

			log.info("Result : " + result);
			out.println(result);
		} catch (KeyStoreException e) {
			String msg = "Error while loading client key pair";
			log.error(msg, e);
			throw new ServletException(msg, e);
		} catch (NoSuchAlgorithmException e) {
			String msg = "No such method exception";
			log.error(msg, e);
			throw new ServletException(msg, e);
		} catch (CertificateException e) {
			String msg = "Certificate exception";
			log.error(msg, e);
			throw new ServletException(msg, e);
		} catch (UnrecoverableEntryException e) {
			String msg = "Unable to reacover entry";
			log.error(msg, e);
			throw new ServletException(msg, e);
		} catch (JOSEException e) {
			String msg = "Error while signing the JWT";
			log.error(msg, e);
			throw new ServletException(msg, e);
		}
	}

	/***
	 * Sends a PUT request to the endpoint
	 * 
	 * @param req
	 *            - request object
	 * @param resp
	 *            - response object
	 * @param salary
	 *            - a value to be used in the payload
	 * @throws IOException
	 * @throws ServletException
	 */
	private void sendPUTRequest(HttpServletRequest req,
			HttpServletResponse resp, String salary) throws IOException,
			ServletException {
		PrintWriter out = resp.getWriter();
		KeyPair clientKeyPair;
		// create a new JSON payload
		String payload = "{\n" + "  \"_putemployee\": {\n"
				+ "    \"employeeNumber\" : \"1002\",\n"
				+ "    \"lastName\": \"Samith\",\n"
				+ "    \"firstName\": \"Will\",\n"
				+ "    \"email\": \"will@samith.com\",\n"
				+ "    \"salary\": \"" + salary + "\"\n" + "  }\n" + "}";
		try {
			// load client's key pair from the key store
			clientKeyPair = loadClientKeyPair();
			SignedJWT signedJWT = getSignedJWT(payload,
					clientKeyPair.getPublic(), clientKeyPair.getPrivate());

			// load the server's public key from the trust store
			PublicKey serverPublicKey = getServerPublicKey();
			// encrypt the signed JWT using server'ss public key
			String encryptedJWT = getEncryptedJWT(signedJWT, serverPublicKey);

			HttpClient client = new HttpClient();
			PutMethod putMethod = new PutMethod(serviceURL + "employee/");
			RequestEntity entity = new StringRequestEntity(encryptedJWT,
					"application/jwt", "utf-8");
			putMethod.setRequestEntity(entity);

			log.info("Sending encrypted JWT with the payload : " + payload);
			int resultCode = client.executeMethod(putMethod);
			String result = readPayload(putMethod.getResponseBodyAsStream());

			out.println(result);
		} catch (KeyStoreException e) {
			String msg = "Error while loading client key pair";
			log.error(msg, e);
			throw new ServletException(msg, e);
		} catch (NoSuchAlgorithmException e) {
			String msg = "No such method exception";
			log.error(msg, e);
			throw new ServletException(msg, e);
		} catch (CertificateException e) {
			String msg = "Certificate exception";
			log.error(msg, e);
			throw new ServletException(msg, e);
		} catch (UnrecoverableEntryException e) {
			String msg = "Unable to reacover entry";
			log.error(msg, e);
			throw new ServletException(msg, e);
		} catch (JOSEException e) {
			String msg = "Error while signing the JWT";
			log.error(msg, e);
			throw new ServletException(msg, e);
		}
	}

	/***
	 * Load the server's public key from the key store
	 * 
	 * @return
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws UnrecoverableEntryException
	 */
	private PublicKey getServerPublicKey() throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			UnrecoverableEntryException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		String pwd = "mypkpassword";
		FileInputStream fileInputStream = null;
		fileInputStream = new FileInputStream("/tmp/service-keystore.jks");
		keyStore.load(fileInputStream, pwd.toCharArray());
		fileInputStream.close();

		KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(
				pwd.toCharArray());
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore
				.getEntry("servc1_cert", protectionParameter);
		Certificate certificate = privateKeyEntry.getCertificate();
		return certificate.getPublicKey();
	}

	/***
	 * Generate the encrypted JWT using the signed JWT and the server's public
	 * key
	 * 
	 * @param signedJWT
	 *            - the signed JWT
	 * @param serverPublicKey
	 *            - public key of the server
	 * @return - encrypted JWT as a string
	 * @throws JOSEException
	 */
	private String getEncryptedJWT(SignedJWT signedJWT,
			PublicKey serverPublicKey) throws JOSEException {
		JWEHeader jweHeader = new JWEHeader(JWEAlgorithm.RSA_OAEP,
				EncryptionMethod.A128CBC_HS256);
		Payload payload = new Payload(signedJWT);
		JWEObject jweObject = new JWEObject(jweHeader, payload);
		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) serverPublicKey));
		return jweObject.serialize();
	}

	/***
	 * Load the client's key pair from the key store
	 * 
	 * @return - the client's key pair
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws UnrecoverableEntryException
	 */
	private KeyPair loadClientKeyPair() throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException,
			UnrecoverableEntryException {
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		String pwd = "mykspwd";
		FileInputStream fileInputStream = null;
		fileInputStream = new FileInputStream("/tmp/client-keystore.jks");
		keyStore.load(fileInputStream, pwd.toCharArray());
		fileInputStream.close();

		KeyStore.ProtectionParameter protectionParameter = new KeyStore.PasswordProtection(
				pwd.toCharArray());
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore
				.getEntry("client_1", protectionParameter);

		RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry
				.getCertificate().getPublicKey();
		RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry
				.getPrivateKey();

		KeyPair keyPair = new KeyPair(publicKey, privateKey);
		return keyPair;
	}

	/***
	 * Return the signed JWT given the payload and the client's public key and
	 * private key
	 * 
	 * @param payload
	 *            - the payload to the intended REST endpoint, must be stored in
	 *            the JWT claims set with the key "payload"
	 * @param publicKey
	 *            - to be sent with the x5c parameter of the JWS which will be
	 *            used in server side for verification of signature
	 * @param privateKey
	 *            - the client's private key to be used for signing the JWS
	 * @return - a Signed JWT object
	 * @throws JOSEException
	 */
	private SignedJWT getSignedJWT(String payload, PublicKey publicKey,
			PrivateKey privateKey) throws JOSEException {
		// claims generation
		JWTClaimsSet jwtClaims = new JWTClaimsSet();
		jwtClaims.setIssuer("test-user");
		jwtClaims.setSubject("WSO2");
		List<String> aud = new ArrayList<String>();
		jwtClaims.setAudience(aud);
		jwtClaims.setExpirationTime(new Date(
				new Date().getTime() + 1000 * 60 * 10));
		jwtClaims.setNotBeforeTime(new Date());
		jwtClaims.setIssueTime(new Date());
		jwtClaims.setJWTID(UUID.randomUUID().toString());
		if (payload != null) {
			jwtClaims.setClaim("payload", payload);
		}

		List<Base64> certChain = new LinkedList<Base64>();
		String encodedPubKey = new BASE64Encoder().encode(publicKey
				.getEncoded());
		Base64 base64 = new Base64(encodedPubKey);
		certChain.add(base64);

		// create JWS header
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.x509CertChain(certChain).build();

		// sign header + payload
		SignedJWT signedJWT = new SignedJWT(jwsHeader, jwtClaims);
		JWSSigner jwsSigner = new RSASSASigner((RSAPrivateKey) privateKey);
		signedJWT.sign(jwsSigner);

		return signedJWT;
	}

	/***
	 * Read the payload from an input stream
	 * 
	 * @param inputStream
	 * @return
	 */
	private String readPayload(InputStream inputStream) {
		BufferedReader bufferedReader;
		bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
		StringBuilder stringBuilder = new StringBuilder();
		String line;
		try {
			while ((line = bufferedReader.readLine()) != null) {
				stringBuilder.append(line.trim());
			}
		} catch (IOException e) {
			log.error("Error while reading the payload from input stream", e);
		}
		return stringBuilder.toString();
	}

}
