/* ==============================================
 * Copyright 2003 Mort Bay Consulting Pty Ltd. All rights reserved.
 * Distributed under the artistic license.
 * Created on 16/04/2004
 * $Id: User.java,v 1.1 2006/01/21 17:28:01 gregw Exp $
 * ============================================== */
 
package com.mortbay.iwiki;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

/* ------------------------------------------------------------------------------- */
/** 
 * 
 * @version $Revision: 1.1 $
 * @author gregw
 */
public class User
{
    private static ThreadLocal current = new ThreadLocal();

    
    public static final String
        OWNER="OWNER",
        MANAGER="MANAGER",
        EDITOR="EDITOR",
        RESIDENT="RESIDENT",
        VIEWALL="VIEWALL",
        ADMIN="ADMIN",
        ACTAS="ACTAS";
       
    public static final User NOBODY =  new User("Nobody");
    public static final User INTERNET = new User("Internet");
    public static final User SYSTEM = new User("System");
    public static final User BANKPASS = new User("BankPass");
    public static final User XPAY = new User("XPay");

    static
    {
        SYSTEM.roles.add(MANAGER);
        BANKPASS.roles.add(MANAGER);
        XPAY.roles.add(MANAGER);
    }

    private static HashMap users = new HashMap();
    private static User[] userArray;
    
    
    public static User fromString(String name, String data)
    {
        User user = new User(name);
        try
        {
            String[] tok = data.split(":");
            int i=0;
            
            user.credential = URLDecoder.decode(tok[i++], "UTF-8");
            if ("*".equals(user.credential)) 
            user.credential = null;
            user.fullName = URLDecoder.decode(tok[i++], "UTF-8");
            user.email=tok[i++];
            user.contact= URLDecoder.decode(tok[i++], "UTF-8");
            user.lang=tok[i++];
            
            while (i < tok.length)
            {
                String role = tok[i++].trim();
                int l = role.indexOf('[');
                if (l < 0)
                    user.roles.add(role.toUpperCase());
                else
                {
                    String r = role.substring(0, l).toUpperCase();
                    user.roles.add(r);
                    Set set = null;
                    if (OWNER.equals(r))
                        set = user.owns;
                    else if (MANAGER.equals(r))
                        set = user.manages;
                    else if (ACTAS.equals(r))
                        set = user.actAs;
                    else
                        continue;
                    StringTokenizer tok2 = new StringTokenizer(role.substring(l + 1,
                            role.length() - 1), ",");
                    while (tok2.hasMoreTokens())
                        set.add(tok2.nextToken().trim().toLowerCase());
                }
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return user;
    }
    
    public static synchronized User getUser(String name)
    {
        return (User)users.get(name);
    }
    
    public static synchronized User getCurrentUser()
    {
        User user = (User)current.get();
        return user==null?NOBODY:user;
    }
    
    public static synchronized String getUserLink(String name)
    {
        User user = getUser(name);
        if (user==null)
            return "-";
        if (user.getEmail()==null || user.getEmail().length()==0)
            return user.getFullName()+" "+user.getContact();
        return "<a href=\"mailto:"+user.getEmail()+
          "\">&lt;"+user.getFullName()+"&gt;</a> "+user.getContact();
    }
    
    public static synchronized User getDefaultManager()
    {
        User m = getUser("borgo");
        if (m==null || m.getEmail()==null)
            m = User.fromString("borgo","*:Borgo+Telematico+srl:borgotelematico@colletta-it.com:%2B390182778274:it:MANAGER");
            return m;
    }
    
    public static String hash(String name, String cred)
    {
        try
        {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.reset();
            if (name!=null)
                md.update(name.getBytes("UTF-8"));
            if (cred!=null)
                md.update(cred.getBytes("UTF-8"));
            byte[] bytes = md.digest();
            StringBuffer buf=new StringBuffer();
            for (int i=0;i<bytes.length;i++)
                buf.append(Integer.toString(bytes[i],16));
            return buf.toString();
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    static public synchronized void loadUsers(URL userproperties)
    {
        try
        {
            users.clear();
            
            InputStream in = userproperties.openStream();
                
            if (in==null)
                return;
            
            Properties props = new Properties();
            props.load(in);
            
            Iterator iter = props.keySet().iterator();
            while(iter.hasNext())
            {
                String name = (String)iter.next();
                String data = props.getProperty(name);
                User user=User.fromString(name, data);
                users.put(name, user);
            }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        
        userArray=(User[])users.values().toArray(new User[users.size()]);
        
    }
    

    static public synchronized void saveUsers(URL userproperties)
    {
        try
        {
            File new_file = new File(new URI(userproperties.toString()+".new"));
            File file = new File(new URI(userproperties.toString()));
            File sav_file = new File(new URI(userproperties.toString()+".sav"));
            if (new_file.exists())
                new_file.delete();
            
            OutputStream out = new FileOutputStream(new_file);
            for (int i=0;i<userArray.length;i++)
            {
                out.write(userArray[i].dump().getBytes("ISO8859_1"));
                out.write(13);
                out.write(10);
            }
            out.close();
            
            if (sav_file.exists())
                sav_file.delete();
            file.renameTo(sav_file);
            new_file.renameTo(file);
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
    
    
    public static User[] getUsers()
    {
        return userArray;
    }
    
    public static void main(String[] arg)
    {
        System.err.println(hash(arg[0],arg[1]));
    }
    
    public static void setCurrentUser(User user)
    {
        current.set(user);
    }

    private String name;
    private String credential;
    private String fullName;
    private String email;
    private String contact;
    private String lang;

    Set owns = new HashSet();
    Set roles = new HashSet();
    Set manages = new HashSet();
    Set actAs = new HashSet();
    
    User(String name)
    {
        this.name=name;
    }
    
    public boolean checkCredential(String cred)
    {
        if ("*".equals(credential))
            return false;
        
        if (credential!=null && credential.equals(cred))
            return true;

        if (credential!=null && credential.equals(hash(name,cred)))
            return true;
        
        return false;
    }
    
    /**
     * @return Returns the email.
     */
    public String getEmail()
    {
        return email;
    }
    
    public void setEmail(String email)
    {
        this.email=email;
    }

    /**
     * @return Returns the context.
     */
    public String getContact()
    {
        return contact;
    }

    /**
     * @param phone
     */
    public void setContact(String contact)
    {
       this.contact=contact;
    }

    /**
     * @return Returns the fullName.
     */
    public String getFullName()
    {
        return fullName;
    }

    /**
     * @param name2
     */
    public void setFullName(String name)
    {
        this.fullName=name;
    }

    /**
     * @return Returns the lang.
     */
    public String getLang()
    {
        return lang;
    }
    
    public Set getManages()
    {
        return Collections.unmodifiableSet(manages);
    }
    
    public String getName()
    {
        return name;
    }
    
    public Set getOwns()
    {
        return Collections.unmodifiableSet(owns);
    }
    
    public Set getRoles()
    {
        return Collections.unmodifiableSet(roles);
    }
    
    public boolean is(String role)
    {
        return roles.contains(role);
    }

    public boolean isAdmin()
    {
        return is(ADMIN);
    }
    
    public boolean isEditor()
    {
        return is(EDITOR);
    }
    
    public boolean isManager()
    {
        return is(MANAGER);
    }
    
    public boolean isOwner()
    {
        return is(OWNER);
    }
    
    public boolean isViewAll()
    {
        return is(VIEWALL);
    }

    public boolean managerOf(String apt)
    {
        if (manages.size()==0 && isManager())
            return true;
        if (manages.contains(apt))
            return true;
        return false;
    }
    
    public boolean manages(String apt)
    {
        
        if (managerOf(apt))
            return true;
        if (actAs.size()>0)
        {
            Iterator i=actAs.iterator();
            while(i.hasNext())
            {
                User as = User.getUser((String)i.next());
                if (as!=null && as.managerOf(apt))
                    return true;
            }
        }
        return false;
    }
    
    public boolean owns(String apt)
    {
        return owns.contains(apt);
    }

    public String toString()
    {
        return name;
    }
    
    public String dump() throws UnsupportedEncodingException
    {
        StringBuffer buf = new StringBuffer();
    
        buf.append(name);
        buf.append(':');
        if (credential==null || credential.length()==0)
            buf.append('*');
        else
            buf.append(URLEncoder.encode(credential,"UTF-8"));
        
        buf.append(':');   
        buf.append(URLEncoder.encode(fullName,"UTF-8"));
        
        buf.append(':'); 
        buf.append(email); 
        buf.append(':');  
        buf.append(URLEncoder.encode(contact,"UTF-8"));
        buf.append(':'); 
        buf.append(lang); 
        
        Iterator iter = roles.iterator();
        while (iter.hasNext())
        {
            String role = (String)iter.next();
            buf.append(':');
            buf.append(role);
            
            if (OWNER.equals(role) && owns!=null && owns.size()>0)
                buf.append(owns);
            if (MANAGER.equals(role) && manages!=null && manages.size()>0)
                buf.append(manages);
            if (ACTAS.equals(role) && actAs!=null && actAs.size()>0)
                buf.append(actAs);
        }
        return buf.toString();
    }

    public void changeCredential(String password)
    {
        credential=password;
    }


    
}
