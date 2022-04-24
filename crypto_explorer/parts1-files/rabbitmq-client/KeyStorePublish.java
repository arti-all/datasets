package producer;


import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.GetResponse;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.security.KeyStore;

public class KeyStorePublish
{
    public static void main(String[] args) throws Exception
    {

        char[] keyPassphrase = "MySecretPassword".toCharArray();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream("/Users/maheeka/ESB_WORK/RABBITMQ/rmqca/client/keycert.p12"), keyPassphrase);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyPassphrase);

        char[] trustPassphrase = "rabbitstore".toCharArray();
        KeyStore tks = KeyStore.getInstance("JKS");
        tks.load(new FileInputStream("/Users/maheeka/ESB_WORK/RABBITMQ/usecases/ssl/rabbitstore"), trustPassphrase);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        tmf.init(tks);

        SSLContext c = SSLContext.getInstance("SSL");
        c.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost("localhost");
        factory.setPort(5671);
        factory.useSslProtocol(c);

        Connection conn = factory.newConnection();
        Channel channel = conn.createChannel();

        channel.queueDeclare("queueKS", false, false, false, null);
        String message = "<m:placeOrder xmlns:m=\"http://services.samples\">\n"
                + "    <m:order>\n" + "        <m:price>" + 100
                + "</m:price>\n" + "        <m:quantity>" + 100
                + "</m:quantity>\n" + "        <m:symbol>" + "XX"
                + "</m:symbol>\n" + "    </m:order>\n" + "</m:placeOrder>";
        channel.basicPublish("", "queueKS", null, message.getBytes());



        GetResponse chResponse = channel.basicGet("queueKS", true);
        if(chResponse == null) {
            System.out.println("No message retrieved");
        } else {
            byte[] body = chResponse.getBody();
            System.out.println("Recieved: " + new String(body));
        }


        channel.close();
        conn.close();
    }
}