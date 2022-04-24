/* Jug Management is a web application conceived to manage user groups or 
 * communities focused on a certain domain of knowledge, whose members are 
 * constantly sharing information and participating in social and educational 
 * events. Copyright (C) 2011 Ceara Java User Group - CEJUG.
 * 
 * This application is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU Lesser General Public License as published by the 
 * Free Software Foundation; either version 2.1 of the License, or (at your 
 * option) any later version.
 * 
 * This application is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public 
 * License for more details.
 * 
 * There is a full copy of the GNU Lesser General Public License along with 
 * this library. Look for the file license.txt at the root level. If you do not
 * find it, write to the Free Software Foundation, Inc., 59 Temple Place, 
 * Suite 330, Boston, MA 02111-1307 USA.
 * */
package org.cejug.yougi.entity;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.persistence.*;
import org.cejug.yougi.util.Base64Encoder;

/**
 * Represents the authentication credentials of the user.
 * @author Hildeberto Mendonca  - http://www.hildeberto.com
 */
@Entity
@Table(name="authentication")
public class Authentication implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    private String username;
    
    @Column(nullable=false)
    private String password;
    
    @ManyToOne
    @JoinColumn(name="user_account")
    private UserAccount userAccount;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * @return the hashed password.
     */
    public String getPassword() {
        return password;
    }

    /**
     * Receive a new password, hash it and set the password attribute.
     * @param password row password as informed by the user. This method should
     * be invoked only in case of changing the password.
     */
    public void setPassword(String password) {
        this.password = hashPassword(password);
    }
    

    /**
     * @return the userAccount that is associated to the authentication credentials.
     */
    public UserAccount getUserAccount() {
        return userAccount;
    }

    public void setUserAccount(UserAccount userAccount) {
        this.userAccount = userAccount;
    }

    /**
     * Hash a raw password using the MD5 algorithm.
     * @param rawPassword non-hashed password informed by the user.
     * @return the hashed password.
     */
    public String hashPassword(String rawPassword) {
        MessageDigest md = null;
        byte stringBytes[] = null;
        try {
            md = MessageDigest.getInstance("MD5");
            stringBytes = rawPassword.getBytes("UTF8");
        }
        catch(NoSuchAlgorithmException nsae) {
            throw new SecurityException("The Requested encoding algorithm was not found in this execution platform.", nsae);
        }
        catch(UnsupportedEncodingException uee) {
            throw new SecurityException("UTF8 is not supported in this execution platform.", uee);
        }
         
        byte stringCriptBytes[] = md.digest(stringBytes);
        char[] encoded = Base64Encoder.encode(stringCriptBytes);
        return String.valueOf(encoded);
    }
}