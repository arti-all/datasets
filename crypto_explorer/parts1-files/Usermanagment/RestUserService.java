package com.exoplatform.project.restservice;

import javax.ws.rs.*;
import javax.ws.rs.core.CacheControl;


import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.User;
import org.exoplatform.services.organization.UserHandler;
import org.exoplatform.services.rest.resource.ResourceContainer;
import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.security.SecureRandom;

    /*
    * REST Service for user managment .
    *
    * @author Sabrine Ayachi
    */
    @Path("/usermanagment")
    @Produces("application/json")
    public class RestUserService implements ResourceContainer {


    @GET
    @Path("/addusers/{prefix}/{suffix}/{nbuser}")
    public void AddUsers ( @PathParam("prefix") String pre , @PathParam("suffix") String suff , @PathParam("nbuser") Integer nombre) throws Exception {
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
            user1.setPassword("00000000");
            user1.setDisplayName(pre + co + suff);
            userHandler.createUser(user1, true);
        }
    }

}



