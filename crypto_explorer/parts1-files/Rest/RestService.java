import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.annotation.security.RolesAllowed;
import org.exoplatform.commons.utils.ListAccess;
import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.organization.UserHandler;
import org.exoplatform.services.rest.resource.ResourceContainer;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.IdentityRegistry;
import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by exo on 26/09/16
 */


@Path("/demo")

@Produces("application/json")


public class RestService  implements ResourceContainer {

    @GET

    @Path("/hello/{name}")

    @RolesAllowed({"administrators"})

    public String hello(@PathParam("name") String name) {

        return "Hello " + name;

    }



    @GET

    @Path("/listusers/{offset}")

    public Response getListUserName(@Context SecurityContext sc, @PathParam("offset") Integer offset) {

        JSONArray list = new JSONArray();

        JSONObject jsonObject = new JSONObject();

        String groupToCheck = "/platform/administrators";

        CacheControl cacheControl = new CacheControl();       cacheControl.setNoCache(true);

        cacheControl.setNoStore(true);


        if (sc.getUserPrincipal() == null || !this.isMemberOf(sc.getUserPrincipal().getName(), groupToCheck)) {


            jsonObject.put("rights","NOT-ALLOWED");

            list.put(jsonObject);


        } else {


            OrganizationService organizationService = (OrganizationService) ExoContainerContext.getCurrentContainer()

                    .getComponentInstanceOfType(OrganizationService.class);

            UserHandler userHandler = organizationService.getUserHandler();

            try {

                ListAccess<User> allUsers = userHandler.findAllUsers();



                if(offset == null || offset < 0)

                    offset = 0;

                int limit = 1000;

                int total = limit + offset;

                int totalUsers = allUsers.getSize();



                if(offset < totalUsers && total > totalUsers){

                    total = totalUsers;

                }

                User[] users = null;


                for (int i = offset; i < total; i++) {

                    users = allUsers.load(i,1);

                    jsonObject = new JSONObject();

                    jsonObject.put("username", users[0].getUserName());

                    list.put(jsonObject);

                }

            } catch (Exception e) {

                // TODO Auto-generated catch block

                e.printStackTrace();

            }



        }



        return Response.ok(list.toString(), MediaType.APPLICATION_JSON).cacheControl(cacheControl).build();


    }


    private boolean isMemberOf(String username, String role) {

        ExoContainer container = ExoContainerContext.getCurrentContainer();

        IdentityRegistry identityRegistry = (IdentityRegistry) container.getComponentInstanceOfType(IdentityRegistry.class);

        Identity identity = identityRegistry.getIdentity(username);

        return identity.isMemberOf(role);

    }

/* methode add users */

    @GET
    @Path("/addusers/{pre}/{suff}/{nbuser}/{patch}")

    public void AddUsers ( @PathParam("pre") String pre , @PathParam("suff") String suff , @PathParam("nbuser") Integer nombre , @PathParam("patch") Integer patch) throws Exception {


        JSONArray list = new JSONArray();
        JSONObject jsonObject = new JSONObject();
        CacheControl cacheControl = new CacheControl();
        cacheControl.setNoCache(true);
        cacheControl.setNoStore(true);


        OrganizationService organizationService = (OrganizationService) ExoContainerContext.getCurrentContainer()

                .getComponentInstanceOfType(OrganizationService.class);
        SecureRandom random = new SecureRandom();



        for (int i = 0; i < nombre; i++) {
            String co = new BigInteger(130, random).toString(32);
            UserHandler userHandler = organizationService.getUserHandler();
            User user1 = userHandler.createUserInstance(pre + co + suff);
            user1.setFirstName(pre + co + suff);
            user1.setLastName(pre + co + suff);
            user1.setPassword("000000000000000");
            user1.setDisplayName(pre + co + suff);
            userHandler.createUser(user1, true);
        }


    }
}


