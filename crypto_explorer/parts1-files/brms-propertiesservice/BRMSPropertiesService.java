package org.drools.brmspropertiesservice;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;
import java.util.Enumeration;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

public class BRMSPropertiesService implements BRMSPropertiesServiceMBean {
	private static final String mykey = "brms";

	private Logger log = Logger.getLogger(this.getClass());
	private String brmsPropertiesFilename;

	public String getBrmsPropertiesFilename() {
		return brmsPropertiesFilename;
	}

	public void setBrmsPropertiesFilename(String brmsPropertiesFilename) {
		this.brmsPropertiesFilename = brmsPropertiesFilename;
	}

	public void start() {
		log.info("Starting BRMSPropertiesService");
		loadBRMSProperties();
	}

	public void stop() {
		log.info("Stopping BRMSPropertiesService");
	}
	
	private void loadBRMSProperties() {
		try {
			URL url = this.getClass().getClassLoader().getResource(brmsPropertiesFilename);
			Properties properties = new Properties();
			properties.load(new FileInputStream(new File(url.getPath())));
			
			for (Enumeration e = properties.propertyNames(); e.hasMoreElements();) {
				String key = (String) e.nextElement();
				String encryptedValue = properties.getProperty(key);
		
				String value = decryptBlowfish(encryptedValue);

				System.setProperty(key, value);
			}
		} catch (Exception e) {
			log.error(e.getMessage());
		}
	}

	public static String encryptBlowfish(String val) {
		try {
			SecretKeySpec key = new SecretKeySpec(mykey.getBytes(), "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encoding = cipher.doFinal(val.getBytes());
			return new BigInteger(encoding).toString(16);
		} catch (Exception e) {
			return null;
		}
	}

	public static String decryptBlowfish(String val) {
		try {
			
			SecretKeySpec key = new SecretKeySpec(mykey.getBytes(), "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decrypted = cipher.doFinal(new BigInteger(val, 16).toByteArray());
			return new String(decrypted);
		} catch (Exception e) {
			return null;
		}
	}

	public static void main(String[] args) {
		try {
			// private
			String privKeyStoreURL;
			String privKeyStorePwd;
			String privKeyAlias;
			String privKeyPwd;
			//public
			String pubKeyStoreURL;
			String pubKeyStorePwd;
			
			System.out.println("******* Private keystore data: ");
			System.out.println("1) key store url: ");
			BufferedReader br1 = new BufferedReader(new InputStreamReader(System.in));
			privKeyStoreURL = br1.readLine();
			
			System.out.println("2) key store password: ");
			BufferedReader br2 = new BufferedReader(new InputStreamReader(System.in));
			privKeyStorePwd = br2.readLine();
			
			System.out.println("3) key alias: ");
			BufferedReader br3 = new BufferedReader(new InputStreamReader(System.in));
			privKeyAlias = br3.readLine();
			
			System.out.println("4) key password: ");
			BufferedReader br4 = new BufferedReader(new InputStreamReader(System.in));
			privKeyPwd = br4.readLine();
			
			System.out.println("******* Public keystore data: ");
			System.out.println("1) key store url: ");
			BufferedReader br5 = new BufferedReader(new InputStreamReader(System.in));
			pubKeyStoreURL = br5.readLine();
			
			System.out.println("2) key store password: ");
			BufferedReader br6 = new BufferedReader(new InputStreamReader(System.in));
			pubKeyStorePwd = br6.readLine();
			
			System.out.println("****** Generated Properties: ******");
			System.out.println("****** Copy lines BELOW to $JBOSS_HOME/server/$CONFIG/conf/brms_encrypted_properties.properties");
			
			System.out.println("drools.serialization.private.keyStoreURL=" + encryptBlowfish(privKeyStoreURL));
			System.out.println("drools.serialization.private.keyStorePwd=" + encryptBlowfish(privKeyStorePwd));
			System.out.println("drools.serialization.private.keyAlias=" + encryptBlowfish(privKeyAlias));
			System.out.println("drools.serialization.private.keyPwd=" + encryptBlowfish(privKeyPwd));
			System.out.println("drools.serialization.public.keyStoreURL=" + encryptBlowfish(pubKeyStoreURL));
			System.out.println("drools.serialization.public.keyStorePwd=" + encryptBlowfish(pubKeyStorePwd));
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
