package net.sf.webdav.model;

import javax.jdo.annotations.IdentityType;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

/**
 * The base object that can represent a Folder or File.
 */

@PersistenceCapable(identityType = IdentityType.APPLICATION, detachable="true")
public class DBObject {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.IDENTITY)
    private int id;

    @Persistent
    private String checksum;

    @Persistent
    private String path;
    
    @Persistent
    private String name;

    @Persistent
    private java.util.Date creation;

    @Persistent
    private java.util.Date lastModified;

    private static final int BYTE_CLEANER_FF = 0xFF;
    private static final int BYTE_CLEANER_10 = 0x10;

    public int getId() {
        return (id);
    }

    public void setId(final int objectId) {
        this.id = objectId;
    }

    public String getChecksum() {
        return (checksum);
    }

    public void setChecksum() {
        try {
            java.security.MessageDigest md5 =
                java.security.MessageDigest.getInstance("MD5");
            String fqn = this.path + this.name;
            md5.update(fqn.getBytes());
            byte[] array = md5.digest();

            StringBuffer sb = new StringBuffer();
            for (int j = 0; j < array.length; ++j) {
                int b = array[j] & BYTE_CLEANER_FF;
                if (b < BYTE_CLEANER_10) {
                    sb.append('0');
                }
                sb.append(Integer.toHexString(b));
            }
            this.checksum = sb.toString();
        } catch (java.security.NoSuchAlgorithmException nsae) {
            this.checksum = this.path + this.name;
        }
    }

    public String getPath() {
        return (this.path);
    }

    public void setPath(final String p) {
        this.path = p;
    }

    public String getName() {
        return (name);
    }

    public void setName(final String dbObjectName) {
        this.name = dbObjectName;
    }

    public java.util.Date getCreation() {
        return (creation);
    }

    public void setCreation(final java.util.Date d) {
        this.creation = d;
    }

    public java.util.Date getLastModified() {
        return (lastModified);
    }

    public void setLastModified(final java.util.Date d) {
        this.lastModified = d;
    }

}
