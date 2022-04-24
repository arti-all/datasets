/******************************************************************************** 
 *
 * DESCRIPTION:  FIXML Connection Test Tool - tool for receiving and sending AMQP
 *                                            messages via SSL broker interface
 *
 ********************************************************************************
 */

package de.deutscheboerse.fixml;

import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Properties;

import javax.jms.BytesMessage;
import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.Message;
import javax.jms.MessageConsumer;
import javax.jms.Session;
import javax.jms.TextMessage;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.qpid.AMQConnectionFailureException;
import org.apache.qpid.AMQUnresolvedAddressException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BrokerConnector implements Closeable
{
    protected static enum StoreType { keystore, truststore }
    protected Properties properties;
    protected InitialContext ctx;
    protected Logger logger;
    protected CommonOptions options;
    protected Connection connection;
    protected Session session;

    public BrokerConnector(final CommonOptions options)
    {
        // create logger
        this.logger = LoggerFactory.getLogger(BrokerConnector.class);
        this.options = options;
        this.properties = new Properties();
        String brokerConnStr = null;
        switch (this.options.amqpVersion)
        {
        case AMQP_0_10:
            properties.setProperty("java.naming.factory.initial", "org.apache.qpid.jndi.PropertiesFileInitialContextFactory");
            brokerConnStr = String.format("amqp://:@BcstRcvrConnTest/?brokerlist='tcp://%s:%d?ssl='true'" +
                    "&ssl_cert_alias='%s'&sasl_mechs='EXTERNAL'&ssl_verify_hostname='%s''" +
                    "&sync_publish='all'&sync_ack='true'&maxprefetch='1'", this.options.hostname,
                    this.options.port, this.options.privateKeyAlias, String.valueOf(this.options.verifyHostname));
            break;
        case AMQP_1_0:
            properties.setProperty("java.naming.factory.initial", "org.apache.qpid.jms.jndi.JmsInitialContextFactory");
            brokerConnStr = String.format("amqps://%s:%d?transport.keyStoreLocation=%s&transport.keyStorePassword=%s&" +
                    "transport.trustStoreLocation=%s&transport.trustStorePassword=%s&transport.keyAlias=%s&transport.verifyHost=%s", 
                    this.options.hostname, this.options.port, System.getProperty("javax.net.ssl.keyStore"), 
                    System.getProperty("javax.net.ssl.keyStorePassword"), System.getProperty("javax.net.ssl.trustStore"), 
                    System.getProperty("javax.net.ssl.trustStorePassword"), this.options.privateKeyAlias,
                    String.valueOf(this.options.verifyHostname));
            break;
        default:
            this.logger.error("Unknown AMQP version '" + this.options.amqpVersion + "', connection string is not set");
            break;
        }
        properties.setProperty("connectionfactory.connection", brokerConnStr);
    }

    protected void checkCertStores() throws HandledException
    {
        this.logger.info("Checking truststore and keystore.");
        this.logger.info("Checking truststore:");
        checkCertStore(System.getProperty("javax.net.ssl.trustStore"), System.getProperty("javax.net.ssl.trustStorePassword"), StoreType.truststore);
        this.logger.info("Truststore check passed.");
        this.logger.info("Checking truststore:");
        checkCertStore(System.getProperty("javax.net.ssl.keyStore"), System.getProperty("javax.net.ssl.keyStorePassword"), StoreType.keystore);
        this.logger.info("Keystore check passed.");
        this.logger.info("Truststore and keystore check passed.");
    }
    
    protected void checkCertStore(String storePath, String storePassword, StoreType storeType) throws HandledException
    {
        try
        {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(storePath), storePassword.toCharArray());
            if (storeType == StoreType.keystore)
            {
                if (!ks.isKeyEntry(options.privateKeyAlias))
                {
                    throw new HandledException("Alias '" + options.privateKeyAlias + "' missing in store '" + storePath + "'");
                }   
            }
            this.logger.info("Printing out " + storeType + " file '" + storePath + "':");
            boolean checkHostnames = (storeType == StoreType.truststore) && this.options.verifyHostname;
            boolean hostnameFoundInCertificate = false;
            // print out store certificates
            Enumeration<String> enumeration = ks.aliases();
            while(enumeration.hasMoreElements()) {
                String alias = enumeration.nextElement();
                if (checkHostnames && alias.equals(this.options.hostname))
                {
                        hostnameFoundInCertificate = true;
                }
                System.out.println("Alias name: " + alias);
                Certificate certificate = ks.getCertificate(alias);
                System.out.println(certificate.toString());
            }
            if (checkHostnames && hostnameFoundInCertificate == false)
            {
                throw new HandledException("Hostname '" + this.options.hostname + "' missing in store '" + storePath + "'");
            }
        }
        catch (IOException|KeyStoreException|CertificateException|NoSuchAlgorithmException e)
        {
            throw new HandledException("Error during checking '" + storePath + "', exception: " + e);
        }
    }
    
    protected void connect() throws JMSException, HandledException, NamingException
    {
        ConnectionFactory connectionFactory;
        try
        {
            this.ctx = new InitialContext(properties);
            connectionFactory = (ConnectionFactory) ctx.lookup("connection");
            try
            {
                this.connection = connectionFactory.createConnection();
                this.session = this.connection.createSession(false, Session.CLIENT_ACKNOWLEDGE);
                this.connection.start();
                this.logger.info("Connected");
            }
            catch (JMSException ex)
            {
                if ("Error creating connection: Connection refused".equals(ex.getMessage()))
                {
                    throw new HandledException("Broker is not running on '" + this.options.hostname + "' port '" + this.options.port + "'");
                }
                else if (ex.getMessage().startsWith("Error creating connection:") && ex.getCause() instanceof AMQUnresolvedAddressException)
                {
                    throw new HandledException("Cannot resolve hostname '" + this.options.hostname + "'");
                }
                else if (ex.getMessage().startsWith("Error creating connection: port out of range:") && ex.getCause() instanceof AMQConnectionFailureException)
                {
                    throw new HandledException("Port out of range: '" + this.options.port + "'");
                }
                this.logger.error("Failed to connect or create a session");
                throw ex;
            }
        }
        catch (NamingException ex)
        {
            this.logger.error("Failed to prepare the connection factory");
            throw ex;
        }
    }
    
    protected void consumeMessage(final MessageConsumer messageConsumer, boolean errorOnNoMsg) throws JMSException
    {
        try
        {
            Message msg = messageConsumer.receive(this.options.timeout);

            if (msg == null)
            {
                if (errorOnNoMsg)
                {
                    this.logger.error("No message received");
                }
                else
                {
                    this.logger.info("No message received");
                }
                
            }
            else if (msg instanceof TextMessage)
            {
                TextMessage textMessage = (TextMessage) msg;
                String messageBody = textMessage.getText();
                msg.acknowledge();
                this.logger.info("Text message received, length = " + messageBody.length() + ", content:\n"
                        + messageBody);
            }
            else if (msg instanceof BytesMessage)
            {
                // convert byte buffer to a String first
                BytesMessage bytesMessage = (BytesMessage) msg;
                StringBuilder builder = new StringBuilder();

                for (int i = 0; i < bytesMessage.getBodyLength(); i++)
                {
                    builder.append((char) bytesMessage.readByte());
                }

                msg.acknowledge();
                this.logger.info("Byte message received, length = " + bytesMessage.getBodyLength() + ", content:\n"
                        + builder.toString());
            }
            else
            {
                this.logger.error("Message of unexpected type received");
                msg.acknowledge();
            }
        }
        catch (JMSException ex)
        {
            this.logger.error("Failed to receive a message");
            throw ex;
        }
    }

    public void close()
    {
        try
        {
            if (this.connection != null)
            {
                this.connection.close();
                this.logger.info("Disconnected");
            }
        }
        catch (JMSException ex)
        {
            this.logger.error("Failed to disconnect properly", ex);
            System.exit(1);
        }
    }
}
