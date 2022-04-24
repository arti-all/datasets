package org.ruhan1.test.bpmclient;

import org.apache.cxf.helpers.IOUtils;
import org.kie.api.runtime.KieSession;
import org.kie.api.runtime.manager.RuntimeEngine;
import org.kie.api.runtime.process.ProcessInstance;
import org.kie.remote.client.api.RemoteRuntimeEngineFactory;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by ruhan on 3/21/18.
 */
public class BpmClient
{
    private KieSession session;

    final static int TIMEOUT_S = 120;

    public BpmClient( Configuration config ) throws Exception
    {
        session = initKieSession( config );
    }

    protected KieSession initKieSession( Configuration config ) throws Exception
    {

        RuntimeEngine restSessionFactory;
        restSessionFactory = RemoteRuntimeEngineFactory.newRestBuilder()
                                                       .addDeploymentId( config.getDeploymentId() )
                                                       .addUrl( new URL( config.getBpmBaseUrl() ) )
                                                       .addUserName( config.getUsername() )
                                                       .addPassword( config.getPassword() )
                                                       .addTimeout( TIMEOUT_S )
                                                       .build();

        return restSessionFactory.getKieSession();
    }

    public synchronized boolean startTask( String processId, Map<String, Object> parameters ) throws Exception
    {
        ProcessInstance processInstance = session.startProcess( processId, parameters );
        if ( processInstance == null )
        {
            System.out.println( "Failed to create new process instance." );
            return false;
        }
        System.out.println( ">>> " + processInstance.getId() );
        return true;

    }

    /**
     * Start bmp process.
     * @param args args[0] is repeat times, default 1
     */
    public static void main( String[] args ) throws Exception
    {
        int repeat = 1;
        if ( args.length > 0 )
        {
            repeat = Integer.parseInt( args[0] );
        }

        ignoreSSLCert();

        Configuration config = new Configuration( "config.properties" );

        BpmClient bpmClient = new BpmClient( config );
        Map<String, Object> params = new HashMap<String, Object>();
        params.put( "taskId", 0 );
        params.put( "processParameters", readProcessParameters() );
        params.put( "usersAuthToken", config.getUsersAuthToken() );


        for ( int i = 0; i < repeat; i++ )
        {
            bpmClient.startTask( config.getProcessId(), params );
        }
    }

    private static String readProcessParameters() throws IOException
    {
        File f = new File( "processParameters.json" );
        return IOUtils.toString( new FileInputStream( f ) );
    }

    private static void ignoreSSLCert() throws Exception
    {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager()
        {
            public java.security.cert.X509Certificate[] getAcceptedIssuers()
            {
                return null;
            }

            public void checkClientTrusted( X509Certificate[] certs, String authType )
            {
            }

            public void checkServerTrusted( X509Certificate[] certs, String authType )
            {
            }
        } };

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance( "SSL" );
        sc.init( null, trustAllCerts, new java.security.SecureRandom() );
        HttpsURLConnection.setDefaultSSLSocketFactory( sc.getSocketFactory() );

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier()
        {
            public boolean verify( String hostname, SSLSession session )
            {
                return true;
            }
        };

        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier( allHostsValid );
    }
}
