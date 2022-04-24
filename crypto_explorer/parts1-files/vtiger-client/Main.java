package su.litvak.vtiger;

import org.glassfish.jersey.jackson.JacksonFeature;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws Exception{
        // vTiger web service URL
        final String servceURL = "http://vtiger54.litvak.su/webservice.php";
        // vTiger user name
        final String userName = "admin";
        // vTiger API access key
        final String userAccessKey = "6sSVEhFbmqygRIys";

        /**
         * Create jersey RESTful client
         */
        Client client = ClientBuilder.newClient().register(JacksonFeature.class);

        /**
         * Set up end point
         */
        WebTarget webTarget = client.target(servceURL);
        /**
         * Retrieve challenge string
         */
        Response r = webTarget.queryParam("operation", "getchallenge")
               .queryParam("username", userName)
                .request(MediaType.APPLICATION_JSON_TYPE)
               .get();

        /**
         * Fail when service is unavailable
         */
        if (r.getStatus() != 200) {
            System.out.println("Request failed with status: " + r.getStatus());
            System.exit(1);
        }

        GetChallengeResponse challenge = r.readEntity(GetChallengeResponse.class);

        if (!challenge.success) {
            System.out.println("Get challenge operation was unsuccessful: " + challenge.error.message);
            System.exit(1);
        }

        /**
         * Login using md5(challengeToken + accessKey) string
         */
        r = webTarget
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.form(new Form()
                        .param("operation", "login")
                        .param("username", userName)
                        .param("accessKey", md5(challenge.result.token + userAccessKey))
                ));

        LoginResponse login = r.readEntity(LoginResponse.class);

        if (!login.success) {
            System.out.println("Login operation was unsuccessful: " + login.error.message);
            System.exit(1);
        }

        String sessionId = login.result.sessionName;
        System.out.println("Logged in. Session id = " + sessionId);

        /**
         * Load list of workflows by querying custom web service
         */
        r = webTarget.queryParam("operation", "getworkflows")
                .queryParam("sessionName", sessionId)
                .request(MediaType.APPLICATION_JSON_TYPE).get();

        GetWorkflowResponse response = r.readEntity(GetWorkflowResponse.class);

        /**
         * Print list of workflow descriptions
         */
        System.out.println("Workflows:");
        for (GetWorkflowResponse.Workflow workflow : response.result.values()) {
            System.out.println(workflow.description);
        }

        /**
         * Log out
         */
        webTarget.queryParam("operation", "logout")
                .queryParam("sessionName", sessionId)
                .request().get();

        System.out.println("Logged out");
    }

    /**
     * <p>Calculates md5 for specified string.</p>
     *
     * <p>Result will be prefixed by zeroes in PHP manner because
     * intended to be used for integration with PHP services.</p>
     *
     * @param s     string to calculate md5 sum for
     * @return      md5 sum as hex string
     * @throws NoSuchAlgorithmException
     */
    private static String md5(String s) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(s.getBytes());
        BigInteger hash = new BigInteger(1, md.digest());
        String result = hash.toString(16);
        while(result.length() < 32) {
            result = "0" + result;
        }
        return result;
    }
}
