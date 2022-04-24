/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.chronopolis.notify;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.annotation.security.RolesAllowed;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.PathParam;
import javax.ws.rs.Consumes;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.chronopolis.notify.db.Ticket;
import org.chronopolis.notify.db.TicketManager;

/**
 * Core put / get resources for notifying chronopolis of push or pull requests
 *
 * @author toaster
 */
@Path("notify")
public final class NotifyResource {

    public static final String MD5_HEADER = "Content-MD5";
    private TicketManager tm = new TicketManager();
    private static final Logger LOG = Logger.getLogger(NotifyResource.class);
    @Context
    private HttpServletRequest request;

    public NotifyResource() {
    }

    /**
     * Request retrieval of a complete Bag, response code is set to ACCEPTED
     *
     * @param accountId
     * @param spaceId
     * @param request
     * @return ticket to retrieve transfer status
     *
     */
    @GET
    @Path("{accountId}/{spaceId}")
    @Produces("application/json")
    @RolesAllowed({"Submittor"})
    public Response requestBag(@PathParam("accountId") String accountId,
            @PathParam("spaceId") String spaceId) {
        try {

            NDC.push("S" + accountId);
            LOG.info("Request to retrieve item. ID: " + spaceId + "  Account: " + accountId);


            Ticket ticket = tm.createTicket(accountId, spaceId, null, request.getUserPrincipal());
            MailUtil.sendMessage(ticket, null);

            ResponseBuilder rb = Response.status(Status.ACCEPTED);
            rb.header("Retry-After", "120");
            rb.entity(ticket);

            return rb.build();
        } finally {
            LOG.info("Completed request to retrieve item ID: " + spaceId + " Account: " + accountId);
            NDC.pop();

        }
    }

    /**
     * retrieve a single item from chronopolis
     *
     * @param accountId
     * @param spaceId
     * @param contentId
     * @param request
     * @return ticket id
     */
    @GET
    @Path("{accountId}/{spaceId}/{contentId}")
    @Produces("application/json")
    @RolesAllowed({"Submittor"})
    public Response requestBag(@PathParam("accountId") String accountId,
            @PathParam("spaceId") String spaceId,
            @PathParam("contentId") String contentId) {

        try {

            NDC.push("I" + accountId);
            LOG.info("Request to retrieve item. ID: " + spaceId + "/" + contentId + "  Account: " + accountId);

            Ticket ticket = tm.createTicket(accountId, spaceId, contentId, request.getUserPrincipal());
            MailUtil.sendMessage(ticket, null);

            ResponseBuilder rb = Response.status(Status.ACCEPTED);
            rb.entity(ticket);
            rb.header("Retry-After", "120");
            return rb.build();

        } finally {
            LOG.info("Completed request to retrieve item ID: " + spaceId + "/" + contentId + " Account: " + accountId);
            NDC.pop();

        }

    }

    /**
     * Notify Chronopolis a manifest is available for transfer response status
     * set as follows: SC_BAD_REQUEST malformed manifest or mismatched md5 sum
     * SC_ACCEPTED got, parsed, and e-mailed response
     *
     * @param accountId
     * @param spaceId
     * @return ticket id to be used for status updates
     */
    @PUT
    @Path("{accountId}/{spaceId}")
    @Consumes("text/plain")
    @Produces("application/json")
    @RolesAllowed({"Submittor"})
    public Response putManifest(@PathParam("accountId") String accountId,
            @PathParam("spaceId") String spaceId, @Context HttpHeaders headers,
            @HeaderParam(MD5_HEADER) String digest) {
        try {

            NDC.push("R" + accountId);
            LOG.info("Request to receive space. ID: " + spaceId + " Account: " + accountId);
            //String digest = extractMd5Header(headers);
            LOG.debug("Manifest Digest: " + digest);
            InputStream is = request.getInputStream();
            IngestRequest ir = new IngestRequest(accountId, spaceId);
            MessageDigest md = MessageDigest.getInstance("MD5");
            String computedDigest = ir.readStream(is, md);
            ResponseBuilder rb;

            // handle md5 missing or corrupt
            if (digest == null || !digest.equals(computedDigest)) {
                rb = Response.status(Status.BAD_REQUEST);
                LOG.info("Digest null or mismatch. Observed Header: " + digest + " Computed Digest: " + computedDigest);
                rb.entity("Digest null or mismatch. Observed Header: " + digest + " Computed Digest: " + computedDigest);
                rb.type(MediaType.TEXT_PLAIN_TYPE);
                return rb.build();

            }
            if (ir.hasErrors()) {
                rb = Response.status(Status.BAD_REQUEST);
                rb.type(MediaType.TEXT_PLAIN_TYPE);
                rb.entity("Corrupt lines");
                return rb.build();
            } else {
                Ticket ticket = tm.createTicket(ir, digest, computedDigest);
                MailUtil.sendMessage(ticket, ir);
                rb = Response.status(Status.ACCEPTED);

                //TODO: update response to reasonable value
                rb.header("Retry-After", "120");
                rb.entity(ticket);
            }

            return rb.build();

        } catch (IOException e) {

            LOG.error("Error reading client supplied manifest stream ", e);
            return Response.status(Status.BAD_REQUEST).build();
        } catch (NoSuchAlgorithmException e) {
            // should never happen
            LOG.error(e);
            throw new RuntimeException(e);

        } finally {
            LOG.info("Completed request to receive space. ID: " + spaceId + " Account: " + accountId);
            NDC.pop();

        }

    }
}
