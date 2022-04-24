/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.chronopolis.notify;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import javax.annotation.security.RolesAllowed;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;
import org.apache.log4j.Logger;
import org.apache.log4j.NDC;
import org.chronopolis.notify.db.Ticket;
import org.chronopolis.notify.db.TicketManager;

/**
 * Resource to update or retrieve the status of a current ticket. The following 
 * URL paths are supported in this resources
 * 
 * GET  /status json
 * PUT  /status/[ticket] text/plain
 * GET  /status/[ticket] json
 * POST /status/[ticket] 
 * GET  /status/[ticket]/receipt text/plain
 * GET  /status/[ticket]/manifest text/plain
 * 
 * @author toaster
 */
@Path("status")
public class StatusResource {

    private static final Logger LOG = Logger.getLogger(StatusResource.class);
    private TicketManager tm = new TicketManager();
    @Context
    private HttpServletRequest request;     
    
    private void checkTicket(Ticket t) {
        if (request.isUserInRole("Processor") || tm.checkTicket(t,request.getUserPrincipal()))
                return;
        else {
            throw new WebApplicationException(Status.FORBIDDEN);
        }
    }
    
    /**
     * Return list of all ticket.
     * 
     * @return 
     */
    @GET
    @Produces("application/json")
    @RolesAllowed({"Processor"})
    public List<Ticket> listTickets() {
        return tm.listAll();
    }

    /**
     * retrieve the client receipt. This lists all files accepted by Chron
     * any file NOT listed here have NOT been accepted by chronopolis
     *  - If ticket is in process, the result of this call is undefined
     *  - In all other cases, a receipt manifest will be uploaded
     *  - returns 200/OK w/ manifest or empty if no manifest is attached
     *  - NOT_FOUND on invalid ticket ID
     * 
     *  - TODO: add md5sum manifest to header
     * @param ticketId
     */
    @GET
    @Path("{ticket}/receipt")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed({"Processor","Submittor"})
    public Response retrieveReceiptManifest(@PathParam("ticket") String ticketId) {
        NDC.push("rtrRecpt" + ticketId);
        try {
            LOG.info("Ticket Manifest, ID: " + ticketId);

            Ticket ticket = tm.getTicket(ticketId);
            ResponseBuilder rb;
            if (ticket != null) {
                checkTicket(ticket);
                
                try {
                    return Response.ok(tm.loadReturnManifest(ticketId), "text/plain").build();
                } catch (IOException e) {
                    LOG.error("Error retrieving " + ticketId);
                    throw new RuntimeException(e);
                }
            } else {
                LOG.debug("Returning not-found, ticket ID unknown: " + ticketId);
                rb = Response.status(Status.NOT_FOUND);
                rb.type(MediaType.TEXT_PLAIN_TYPE);
                rb.entity("No such ticket " + ticketId);

            }

            return rb.build();
        } finally {
            LOG.info("Completed ticket manifest attachment: " + ticketId);
            NDC.pop();
        }

    }

    /**
     * retrieve a manifest for a ticket, This manifest is the original manifest as supplied by a chron depositor
     *  - returns 200/OK w/ manifest or empty if no manifest is attached
     *  - NOT_FOUND on invalid ticket ID
     * 
     *  - TODO: add md5sum manifest to header
     * 
     * @param ticketId
     * @return 
     */
    @GET
    @Path("{ticket}/manifest")
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed({"Processor","Submittor"})
    public Response retrieveManifest(@PathParam("ticket") String ticketId) {
        NDC.push("rtrMf" + ticketId);
        try {
            LOG.info("Ticket Manifest, ID: " + ticketId);

            Ticket ticket = tm.getTicket(ticketId);
            ResponseBuilder rb;
            if (ticket != null) {
                checkTicket(ticket);
                try {
                    return Response.ok(tm.loadPutManifest(ticketId), "text/plain").build();
                } catch (IOException e) {
                    LOG.error("Error retrieving " + ticketId);
                    throw new RuntimeException(e);
                }
            } else {
                LOG.debug("Returning not-found, ticket ID unknown: " + ticketId);
                rb = Response.status(Status.NOT_FOUND);
                rb.type(MediaType.TEXT_PLAIN_TYPE);
                rb.entity("No such ticket " + ticketId);

            }

            return rb.build();
        } finally {
            LOG.info("Completed ticket manifest attachment: " + ticketId);
            NDC.pop();
        }
    }

    /**
     * Attach a receipt manifest to a ticket
     *  - this should only be called on ticket types of Get it
     *  - for put requests, calls to this will error
     *  - on successful upload, response will be set to 200/OK
     *  - NOT_FOUND on invalid ticket ID
     *  - BAD_REQUEST on closed/errored ticket or on mismatched digest
     * 
     * TODO: What should be returned if we encounter formatting errors? Currently, we will still return OK
     * 
     * @param ticketId
     * @return 
     */
    @PUT
    @Path("{ticket}")
    @Consumes(MediaType.TEXT_PLAIN)
    @RolesAllowed({"Processor"})
    public Response attachReceiptManifest(@PathParam("ticket") String ticketId, @Context HttpServletRequest request,
            @HeaderParam(NotifyResource.MD5_HEADER) String digest) {
        NDC.push("putRcpt" + ticketId);
        try {
            LOG.info("Ticket Request ID: " + ticketId);

            Ticket ticket = tm.getTicket(ticketId);
            InputStream is = request.getInputStream();
            IngestRequest ir = new IngestRequest();
            MessageDigest md = MessageDigest.getInstance("MD5");
            String computedDigest = ir.readStream(is, md);


            ResponseBuilder rb;
            // BAD_REQUEST on digesting errors
            if (digest == null || !digest.equals(computedDigest)) {
                rb = Response.status(Status.BAD_REQUEST);
                LOG.info("Digest null or mismatch. Observed Header: " + digest + " Computed Digest: " + computedDigest);
                rb.entity("Digest null or mismatch. Observed Header: " + digest + " Computed Digest: " + computedDigest);
                rb.type(MediaType.TEXT_PLAIN_TYPE);
                return rb.build();

            }

            if (ticket != null) {

                if (ticket.getStatus() != Ticket.STATUS_OPEN) {
                    LOG.debug("Attempt to attach manifest to closed ticket " + ticketId);
                    rb = Response.status(Status.BAD_REQUEST);
                    rb.type(MediaType.TEXT_PLAIN_TYPE);
                    rb.entity("Attempt to attach manifest to closed ticket " + ticketId);

                } else {
                    tm.setTicketReturnManifest(ir, ticket);
                    rb = Response.ok();
                }
            } else {
                LOG.debug("Returning not-found, ticket ID unknown: " + ticketId);
                rb = Response.status(Status.NOT_FOUND);
                rb.type(MediaType.TEXT_PLAIN_TYPE);
                rb.entity("No such ticket " + ticketId);

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
            LOG.info("Completed ticket manifest attachment: " + ticketId);
            NDC.pop();
        }
    }

    /**
     * response set to 
     *      200/OK for open tickets return application/json 
     *      201/CREATED for successfully finished tickets, (status=1)
     *          will return a json object w/ status=1
     *      500/INTERNAL ERROR for requests that errored out, ticket json in body
     *          status > 1 will be set
     *      404/NOT_FOUND for non-existent tickets
     * 
     * @param ticket
     * @param response
     * @return ticket object
     */
    @GET
    @Path("{ticket}")
    @Produces("application/json")
    @RolesAllowed({"Processor","Submittor"})
    public Response getStatus(@PathParam("ticket") String ticketId) {
        try {

            NDC.push("getStatus" + ticketId);
            LOG.info("Ticket Request ID: " + ticketId);

            Ticket ticket = tm.getTicket(ticketId);
            ResponseBuilder rb;
            if (ticket != null) {
                checkTicket(ticket);

                switch (ticket.getStatus()) {
                    case Ticket.STATUS_OPEN:
                        rb = Response.status(Status.OK).header("Retry-After", "120").entity(ticket);
                        break;
                    case Ticket.STATUS_FINISHED:
                        rb = Response.status(Status.CREATED).entity(ticket);
                        break;
                    default:
                        rb = Response.status(Status.INTERNAL_SERVER_ERROR).entity(ticket);
                }

            } else {
                LOG.debug("Returning not-found, ticket ID unknown: " + ticketId);
                rb = Response.status(Status.NOT_FOUND);
                rb.type(MediaType.TEXT_PLAIN_TYPE);
                rb.entity("No such ticket " + ticketId);

            }

            return rb.build();
        } finally {
            LOG.info("Completed Ticket Request ID: " + ticketId);
            NDC.pop();
        }
    }

    /**
     * Update the running state of a ticket
     *  Returns following codes:
     *   - BAD_REQUEST - ticket is not in open state, or return manifest has not been set
     *   - NOT_FOUND - ticket does not exist
     *   - OK - ticket  updated
     *      
     * @param ticket
     * @param resultCode
     * @param response 
     */
    @POST
    @Path("{ticket}")
    @RolesAllowed({"Processor"})
    public Response setStatus(@PathParam("ticket") String ticket,
            @FormParam("resultCode") int resultCode,
            @FormParam("description") String description) {

        try {
            NDC.push("setStatus" + ticket);
            LOG.info("Ticket Request ID: " + ticket + " resultCode: " + resultCode);

            Ticket t = tm.getTicket(ticket);
            if (t == null) {
                return Response.status(Status.NOT_FOUND).build();
            }
            if (t.getStatus() != Ticket.STATUS_OPEN) {
                LOG.debug("Attempt to update closed ticket " + ticket);
                return Response.status(Status.BAD_REQUEST).build();
            }

            if ((resultCode == 1) && !tm.hasReturnManifest(ticket)) {
                LOG.debug("Attempt to mark ticket successful w/o manifest " + ticket);
                return Response.status(Status.BAD_REQUEST).build();
            }
   

            tm.setTicketStatus(ticket, description, resultCode);

            return Response.ok().build();
        } finally {
            LOG.info("Completed Ticket Request ID: " + ticket);
            NDC.pop();
        }
    }
}
