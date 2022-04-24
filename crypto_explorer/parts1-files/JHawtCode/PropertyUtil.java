package com.ddubyat.develop.jhawtcode.util;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.annotation.PostConstruct;
import javax.xml.bind.DatatypeConverter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * PropertyUtil is used to set system properties and check system property for ability to execute dynamic code
 *
 * @author dwtalk
 * @version 1.0.2
 * @since 2014-07-15
 */
@Service
public class PropertyUtil {

    private static Logger log = LoggerFactory.getLogger(PropertyUtil.class);

    @Autowired
    private ApplicationContext applicationContext;

    public static String license = "Full Function - Unsupported";
    private static Boolean isCanHawt;

    /**
     * Service method to set a system property during runtime
     * @param propertyKey The system property key to set
     * @param propertyValue The system property value to set
     * @return The value of the set system property
     */
    public String setProp(String propertyKey, String propertyValue) {
        log.debug("System Property {} set to {}", propertyKey, propertyValue);
        return System.setProperty(propertyKey.trim(), propertyValue.trim());
    }

    /**
     * Internal startup check to ensure runnable
     */
    @PostConstruct
    public void startupCheck() {
        canHawtTheCode();
    }

    /**
     * Internal check to see if dynamic code execution is enabled
     * @return true if enabled or false if disabled
     */
    public Boolean canHawtTheCode() {
        if(isCanHawt!=null) {
            return isCanHawt;
        }

        String enableProp = System.getProperty("jhawtcode.enabled");
        log.trace("Check for jhawtenabled: {}", enableProp);
        if(enableProp != null && !StringUtils.isEmpty(enableProp) && enableProp.equalsIgnoreCase("ICERTIFYTHISISNOTPROD")) {
            isCanHawt = Boolean.TRUE;
            String licProp = System.getProperty("jhawtcode.license");
            if(!StringUtils.isEmpty(licProp)) {
                try {
                    String email = licProp.split(":")[0];
                    String licenseCode = licProp.split(":")[1];
                    if(validLicense(email, licenseCode)) {
                        license = email;
                    }
                } catch (Exception e) {
                    license = "Unlicensed";
                }
            }
            printLicense();
        } else {
            isCanHawt = Boolean.FALSE;
        }

        return isCanHawt;
    }

    private boolean validLicense(String email, String licenseCode) throws Exception {

        Resource res = applicationContext.getResource("classpath:jhc-public.der");
        InputStream is = res.getInputStream();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        byte[] buffer = new byte[4096];
        byte[] pkey;
        int stream;
        while ((stream = is.read(buffer, 0, buffer.length)) != -1) {
            baos.write(buffer, 0, stream);
        }

        pkey = baos.toByteArray();

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pkey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey mypk = keyFactory.generatePublic(keySpec);

        Signature instance = Signature.getInstance("SHA1withRSA");
        instance.initVerify(mypk);
        instance.update(email.getBytes());

        //BASE64Decoder decoder = new BASE64Decoder();
        //byte[] decodedBytes = decoder.decodeBuffer(licenseCode);

        return instance.verify(DatatypeConverter.parseBase64Binary(licenseCode));
    }

    private static synchronized void printLicense() {
        System.out.println("/*****************************************/");
        System.out.println("---------------- JHawtCode ----------------");
        System.out.println("Licensed for: " + license);
        System.out.println("/*****************************************/");
    }

}
