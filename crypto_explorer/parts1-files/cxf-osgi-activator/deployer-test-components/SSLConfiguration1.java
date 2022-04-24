/*
 * Copyright 2017 mnn.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.mnybon.deployer.testresources.jettyconfig;

import com.github.mnybon.deployer.jetty.service.EngineConfiguration;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import org.apache.cxf.configuration.jsse.TLSServerParameters;
import org.osgi.service.component.annotations.Component;
import org.apache.cxf.configuration.security.ClientAuthentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author mnn
 */
@Component(immediate = true)
public class SSLConfiguration1 implements EngineConfiguration{
    private static final Logger LOGGER = LoggerFactory.getLogger(SSLConfiguration1.class);
    
    @Override
    public int getConfiguredPort() {
        return 9191;
    }

    @Override
    public TLSServerParameters getTLSParameters() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException, CertificateException {
        TLSServerParameters params = new TLSServerParameters();
        
        KeyStore myCerts = KeyStore.getInstance("Windows-MY", "SunMSCAPI");
        KeyStore rootCerts = KeyStore.getInstance("Windows-ROOT", "SunMSCAPI");
      
        myCerts.load(null, null);
        rootCerts.load(null, null);
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(rootCerts);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(myCerts, "".toCharArray());
        
        params.setTrustManagers(tmf.getTrustManagers());
        params.setKeyManagers(kmf.getKeyManagers());
        
        params.setClientAuthentication(new ClientAuthentication());
        
        Enumeration<String> userAliases = myCerts.aliases();
        Enumeration<String> rootAliases = myCerts.aliases();
        
        while(userAliases.hasMoreElements()){
            LOGGER.info("UserCert: "+myCerts.getCertificate(userAliases.nextElement()));
        }
        while(rootAliases.hasMoreElements()){
            LOGGER.info("RootCert: "+rootCerts.getCertificate(rootAliases.nextElement()));
        }
        
        return params;
        
    }
    
    
    
}
