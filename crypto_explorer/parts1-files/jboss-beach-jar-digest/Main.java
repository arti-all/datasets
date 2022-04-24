/*
 * JBoss, Home of Professional Open Source.
 * Copyright (c) 2012, Red Hat, Inc., and individual contributors
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
package org.jboss.beach.jar.digest;

import sun.misc.BASE64Encoder;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

/**
 * Create a digest for a jar ignoring any timestamped bits.
 *
 * @author <a href="mailto:cdewolf@redhat.com">Carlo de Wolf</a>
 */
public class Main {
    private static BASE64Encoder encoder = new BASE64Encoder();

    private static byte[] digest(final String fileName, final boolean showEntries) throws NoSuchAlgorithmException, IOException {
        // TODO: make the algorithm choice configurable
        final MessageDigest jarDigest = MessageDigest.getInstance("SHA1");
        final MessageDigest digest = MessageDigest.getInstance("SHA1");
        final JarInputStream in = new JarInputStream(new BufferedInputStream(new FileInputStream(fileName)));
        int numEntries = 0;
        try {
            JarEntry entry;
            final SortedMap<String, byte[]> digests = new TreeMap<String, byte[]>();
            while ((entry = in.getNextJarEntry()) != null) {
                numEntries++;

                // do not hash directories
                if (entry.isDirectory())
                    continue;

                final String name = entry.getName();
                // do not hash information added by jarsigner
                if (name.startsWith("META-INF/")) {
                    if (name.endsWith(".SF") || name.endsWith(".DSA") || name.endsWith(".RSA"))
                        continue;
                }
                if (name.equals("META-INF/INDEX.LIST"))
                    continue;

                // depending on the tool used to 'zip' up, MANIFEST.MF may or may not be a jar entry
                // to allow comparison we ignore MANIFEST.MF for the moment.
                if (name.equals("META-INF/MANIFEST.MF"))
                    continue;

                // do not hash timestamped maven artifacts
                // TODO: make this optional, enabled by default
                if (name.startsWith("META-INF/maven/") && name.endsWith("/pom.properties"))
                    continue;

                digest.reset();
                final byte[] buf = new byte[4096];
                int l;
                while ((l = in.read(buf)) > 0)
                    digest.update(buf, 0, l);
                final byte[] d = digest.digest();
                digests.put(name, d);
            }
            for(SortedMap.Entry<String, byte[]> digestEntry : digests.entrySet()) {
                final byte[] d = digestEntry.getValue();
                if (showEntries) {
                    System.out.println("Name: " + digestEntry.getKey());
                    System.out.println("SHA1-Digest: " + encoder.encode(d));
                    System.out.println();
                }
                jarDigest.update(d);
            }
        } finally {
            in.close();
        }

        if (numEntries == 0) {
            // did not find any entries? then its not a jar file probably (or a zero size one). In any case digest it.
            final InputStream fin = new BufferedInputStream(new FileInputStream(fileName));
            try {
                final byte[] buf = new byte[4096];
                int l;
                while ((l = fin.read(buf)) > 0)
                    jarDigest.update(buf, 0, l);
            } finally {
                fin.close();
            }
        }
        return jarDigest.digest();
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("Usage: Main [-s] <file>...");
            System.exit(1);
        }
        boolean showEntries = false;

        for (String fileName : args) {
            // TODO: make sensible options and process them properly
            if (fileName.equals("-s"))
                showEntries = true;
            else {
                // TODO: make output format configurable
                final byte[] digest = digest(fileName, showEntries);
                if (showEntries)
                    System.out.print("Jar-SHA1-Digest: ");
                else
                    System.out.print(fileName + ": ");
                System.out.println(encoder.encode(digest));
            }
        }
    }
}
