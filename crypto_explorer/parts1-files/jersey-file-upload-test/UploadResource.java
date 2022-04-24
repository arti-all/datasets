package com.palominolabs.jersey;

import com.sun.jersey.multipart.FormDataBodyPart;
import com.sun.jersey.multipart.FormDataParam;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.google.common.io.Closeables.closeQuietly;

@Path("resource-test")
public final class UploadResource {
    private static final Logger logger = LoggerFactory.getLogger(UploadResource.class);

    // just to easily test if resource is wired
    @GET
    public String get() {
        return this.getClass().getCanonicalName();
    }

    @POST
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public String upload(@FormDataParam("file") FormDataBodyPart file) throws NoSuchAlgorithmException, IOException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        InputStream is = file.getValueAs(InputStream.class);

        try {

            BufferedInputStream bis = new BufferedInputStream(is);

            int r = 0;
            try {
                r = bis.read();

                while (r != -1) {
                    md5.update((byte) r);
                    r = bis.read();
                }
            } catch (IOException e) {
                logger.warn("Uh oh", e);
                throw e;
            } finally {
                closeQuietly(bis);
            }
        } finally {
            closeQuietly(is);
        }

        return Hex.encodeHexString(md5.digest());
    }
}
