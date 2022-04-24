/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.kabir.github.merges.common;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

public class Util {

    public static File getExistingDirectory(String path) {
        File dir = new File(path);
        if (!dir.exists()) {
            throw new IllegalArgumentException("Cannot find " + path);
        }
        if (!dir.isDirectory()){
            throw new IllegalArgumentException(path + " is not a directory.");
        }
        return dir;
    }

    public static void recursiveDelete(File file) {
        if (file.exists()){
            if (file.isDirectory()){
                for (File child : file.listFiles()){
                    recursiveDelete(child);
                }
            }
            file.delete();
        }
    }

    public static File createDirectoryAndMakeSureExists(File parent, String name) {

        File dir = new File(parent, name);
        if (!dir.exists()) {
            dir.mkdirs();
            if (!dir.exists()){
                throw new RuntimeException("Could not create " + dir.getAbsolutePath());
            }
        }
        if (!dir.isDirectory()){
            throw new IllegalArgumentException(dir.getAbsolutePath() + " is not a directory.");
        }
        return dir;
    }

    public static String md5(String plain) {
        try {
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.update(plain.getBytes(), 0, plain.length());
            String digest = new BigInteger(1,m.digest()).toString(16);
            return digest;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void safeClose(Closeable c){
        try {
            c.close();
        } catch (Exception ignore){
        }
    }

    public static Properties loadProperties(File file) {
        Properties props = new Properties();
        try {
            final InputStream in = new BufferedInputStream(new FileInputStream(file));
            try {
                props.load(in);
                return props;
            } finally {
                safeClose(in);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeProperties(Properties properties, File file) {
        try {
            final OutputStream out = new BufferedOutputStream(new FileOutputStream(file));
            try {
                properties.store(out, null);
            } finally {
                safeClose(out);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
