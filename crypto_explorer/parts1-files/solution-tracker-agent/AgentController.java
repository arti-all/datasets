package com.redhat.sso.solutiontracker.agent;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

//import com.redhat.sso.solutiontracker.analytics.AnalyticsService3;

@Path("/analytics")
public class AgentController{
//  public AnalyticsService3 service3=AnalyticsService3.get();
  private static List<String> hits=new ArrayList<String>();
  private static boolean inMemory=true;
  
  @GET
  @Path("/viewHits")
  public Response viewHits(
      @Context HttpServletRequest request 
      ,@Context HttpServletResponse response
      ,@Context ServletContext servletContext
      ) throws FileNotFoundException, IOException, ServletException{
    
    if (inMemory){
      StringBuffer sb=new StringBuffer();
      synchronized(hits){
        for(String hit:hits)
          sb.append(hit).append("\n");
      }
      return Response.status(200).entity(sb.toString()).build();
    }else{
      return Response.status(200).entity(SingletonLogger.getInstance().readFile(false)).build();
    }
  }

  
  @GET
  @Path("/downloadHits")
  public Response downloadDocumentHits(
      @Context HttpServletRequest request 
      ,@Context HttpServletResponse response
      ,@Context ServletContext servletContext
      ) throws FileNotFoundException, IOException, ServletException{
    if (inMemory){
      StringBuffer sb=new StringBuffer();
      synchronized(hits){
        for(String hit:hits)
          sb.append(hit).append("\n");
      }
      hits.clear();
      return Response.status(200).entity(sb.toString()).build();
    }else{
      return Response.status(200).entity(SingletonLogger.getInstance().readFile(true)).build();
    }
  }
  
  @GET
  @Path("/agent/track/{id}")
  public Response trackDocumentHit(
      @Context HttpServletRequest request 
      ,@Context HttpServletResponse response
      ,@Context ServletContext servletContext
      ,@PathParam("id") String id
      ) throws FileNotFoundException, IOException, ServletException{
    
    if (null!=request.getParameter("ignore")) return Response.status(200).build();
    
    String size="hex-grey";//=null!=request.getParameter("s")?request.getParameter("s"):"x60";
    if (id.contains(":")){
    	size=id.split(":")[1];
    	id=id.split(":")[0];
    }
    
//    Document doc=service3.getDocuments().get(id);
//    if (null==doc) throw new RuntimeException("[/track/"+id+"] Unable to find document");
    
    // log the hit in a file ready to be downloaded
    System.out.println("====================================");
    System.out.println("QueryString = "+request.getQueryString());
    System.out.println("URL = "+request.getRequestURL().toString());
    System.out.println("ContextPath = "+request.getContextPath());
//    System.out.println("UserPrincipal = "+request.getUserPrincipal());
    
    Enumeration headerNames=request.getHeaderNames();
    while (headerNames.hasMoreElements()) {
      String headerName=(String) headerNames.nextElement();
      System.out.println("Header ["+headerName+"] = ["+request.getHeader(headerName)+"]");
    }

    if (null!=request.getCookies()) for (Cookie c : request.getCookies()) {
      System.out.println("Cookie [name="+c.getName()+";value="+c.getValue()+"]");
    }

    Enumeration parameterNames=request.getParameterNames();
    while (parameterNames.hasMoreElements()) {
      String parameterName=(String) parameterNames.nextElement();
      System.out.println("Parameter ["+parameterName+"] = ["+request.getParameter(parameterName)+"]");
    }
    
    System.out.println("====================================");
    
    String user=(String)request.getParameter("user");
    String timestamp=(String)request.getParameter("timestamp");
    String docId=(String)request.getParameter("id");
    
    
    Cookie cid=getCookie(request, "cid-"+id);
    int cookieExpiryInSeconds=300; // 300 = 5 minutes
    if (cid==null)
      response.addCookie(newCookie("cid-"+id, cookieExpiryInSeconds));
    
    if (user==null) user="unknown";
    if (timestamp==null) timestamp=new SimpleDateFormat("yyyy-MM-dd'T'hh:mm:ss").format(new Date());
    
    if (cid==null){
      if (inMemory){
        hits.add(timestamp+"#"+id+"#"+user+(docId!=null?"#"+docId:""));
      }else{
        SingletonLogger.getInstance().writeToFile(timestamp+"#"+id+"#"+user);
      }
    }else{
      System.out.println("ignoring stats increment for (user="+user+"), cookie (id=\"cid-"+id+"\", expiry="+cookieExpiryInSeconds+") exists...");
    }
    
    if (id.startsWith("DOC-") || id.matches("\\d+")){
    	//return serveImage(servletContext, response, "rh-mojo-icons-consulting-inc0340383rm-201512_sso-solution_"+size+".png");
    	return serveImage(servletContext, response, "spm-"+size+"-x100.png");
    }else{
    	
    }
    
//    boolean isAgent=true;
//    if (isAgent){
    return serveImage(servletContext, response, "untracked-"+size+"-x100.png");
      //return serveImage(servletContext, response, "rh-mojo-icons-consulting-inc0340383rm-201512_untracked_"+size+".png");
//    }else{
//      String filenameAddendum = doc.getType().toLowerCase().replaceAll(" ", "-");
//      if (StringUtils.isNotBlank(filenameAddendum)) {
//        return serveImage(servletContext, response, "trackers/rh-mojo-icons-consulting-inc0340383rm-201512_" + filenameAddendum + "_x60.png");
//      } else
//        return serveImage(servletContext, response, "trackers/rh-mojo-icons-consulting-inc0340383rm-201512_sso-solution2.png");
//    }
    
    
//    http://34.230.171.1:8080/solution-tracker/api/analytics/agent/track/251?user=mallen
//    http://34.230.171.1:8080/solution-tracker/api/analytics/track2/252?user=apellack
    
//    return Response.status(200).entity("OK").build();
//    return track(request, response, servletContext, doc);
  }
  
  
  
//  @SuppressWarnings("rawtypes")
//  public Response track(
//      @Context HttpServletRequest request 
//      ,@Context HttpServletResponse response
//      ,@Context ServletContext servletContext
//      ,Document doc
//      ) throws FileNotFoundException, IOException{
//    
//    System.out.println("====================================");
//    System.out.println("QueryString = "+request.getQueryString());
//    System.out.println("URL = "+request.getRequestURL().toString());
//    System.out.println("ContextPath = "+request.getContextPath());
////    System.out.println("UserPrincipal = "+request.getUserPrincipal());
//    
//    Enumeration headerNames=request.getHeaderNames();
//    while (headerNames.hasMoreElements()) {
//      String headerName=(String) headerNames.nextElement();
//      System.out.println("Header ["+headerName+"] = ["+request.getHeader(headerName)+"]");
//    }
//
//    if (null!=request.getCookies()) for (Cookie c : request.getCookies()) {
//      System.out.println("Cookie [name="+c.getName()+";value="+c.getValue()+"]");
//    }
//
//    Enumeration parameterNames=request.getParameterNames();
//    while (parameterNames.hasMoreElements()) {
//      String parameterName=(String) parameterNames.nextElement();
//      System.out.println("Parameter ["+parameterName+"] = ["+request.getParameter(parameterName)+"]");
//    }
//    
//    System.out.println("====================================");
//    
//    String user=(String)request.getParameter("user");
//    String role=(String)request.getParameter("role");
//    String dept=(String)request.getParameter("dept");
//    String geo=(String)request.getParameter("geo");
//    String count=(String)request.getParameter("count");
//    String timestamp=(String)request.getParameter("timestamp");
//    
//    Cookie cid=getCookie(request, "cid)");
//    
//    int cookieExpiryInSeconds=300; // 300 = 5 minutes
//    
//    if (cid==null)
//      response.addCookie(newCookie("cid", cookieExpiryInSeconds));
//    
//    if (user!=null && (geo==null || dept==null || role==null)){
//      UserController uc=new UserController();
//      List<User> users=uc.search("uid", user);
//      if (users.size()==1){
//        User realUser=users.iterator().next();
//        if (role==null)
//          role=realUser.getTitle();
//        if (dept==null)
//          dept=realUser.getRhatCostCenterDesc();
//        if (geo==null)
//          geo=realUser.getRhatGeo();
//        System.out.println("Looked up user ["+user+"] role["+role+"] dept["+dept+"] geo["+geo+"]");
//      }
//    }
//    
//    if (user==null) user="unknown";
//    if (geo==null) geo="unknown";
//    if (dept==null) dept="unknown";
//    if (role==null) role="unknown";
//    if (count==null) count="1";
//    if (timestamp==null) timestamp=new SimpleDateFormat("yyyy-MM-dd'T'hh:mm:ss").format(new Date());
//    
//    if (cid==null){
//      service3.track(timestamp, doc, user, role, dept, geo, count);
//    }else{
//      System.out.println("ignoring stats increment for (user="+user+"; dept="+dept+"; geo="+geo+"), cid cookie (expiry="+cookieExpiryInSeconds+") exists...");
//    }
//    
//    String accept=request.getHeader("Accept");
//    System.out.println("accept = "+accept);
//    
//    String filenameAddendum = doc.getType().toLowerCase().replaceAll(" ", "-");
//    if (StringUtils.isNotBlank(filenameAddendum)) {
//      return serveImage(doc, servletContext, response, "trackers/rh-mojo-icons-consulting-inc0340383rm-201512_" + filenameAddendum + "_x60.png");
//    } else
//      return serveImage(doc, servletContext, response, "trackers/rh-mojo-icons-consulting-inc0340383rm-201512_sso-solution2.png");
//  }
  
  private Cookie newCookie(String name, Integer ageInSecondsWhenTheCookieWillExpire){
    SecureRandom random = new SecureRandom();
    Cookie cookie=new Cookie(name,new BigInteger(130, random).toString(32));
    cookie.setMaxAge(ageInSecondsWhenTheCookieWillExpire);
    return cookie;
  }
  private Cookie getCookie(HttpServletRequest request, String name){
    if (null!=request.getCookies()){
      for(Cookie c:request.getCookies()){
        if (c.getName().equals(name)){
          return c;
        }
      }
    }
    return null;
  }
  
  
  private Response serveImage(ServletContext ctx, HttpServletResponse resp, String imagePath) throws IOException{
    // Get the absolute path of the image
    String filename=ctx.getRealPath(imagePath);
    System.out.println("Serving image/file = "+filename);
    // retrieve mimeType dynamically
    String mime=ctx.getMimeType(filename);
    if (mime==null) {
//      resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      return Response.status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR).build();
    }
  
    resp.setContentType(mime); // or "image/svg+xml" and serve the html
    File file=new File(filename);
    resp.setContentLength((int) file.length());
  
    FileInputStream in=new FileInputStream(file);
    OutputStream out=resp.getOutputStream();
  
    // Copy the contents of the file to the output stream
    byte[] buf=new byte[1024];
    int count=0;
    while ((count=in.read(buf))>=0) {
      out.write(buf, 0, count);
    }
    out.close();
    in.close();
    
    return Response.status(200).build();
  }
  
}