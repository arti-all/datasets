/*
 * Copyright 2014 Bernd Eckenfels, Germany.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 */
package net.eckenfels.mavenplugins.lockdeps;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;


public class ProjectScanner
{
    MavenProject project;
    MessageDigest digest;
    private Map<String, String> checksums;
    private HashMap<String, Artifact> artifacts;

    public ProjectScanner(MavenProject project, String algorithm) throws NoSuchAlgorithmException
    {
        this.project = project;
        this.digest  = MessageDigest.getInstance(algorithm);
        this.checksums = new HashMap<String, String>();
        this.artifacts = new HashMap<String, Artifact>();
    }

    public void writeTo(File currentFile) throws IOException
    {
        PrintWriter fw = new PrintWriter(currentFile, "UTF-8");
        try
        {
            // TODO: sort to minimize changes
            for(Entry<String, String> e : checksums.entrySet())
            {
                fw.printf("+ %s %s%n", e.getValue(), e.getKey());
            }
        }
        finally
        {
            fw.close();
        }
    }

    public void scan() throws IOException
    {
        Set<Artifact> deps = project.getArtifacts();

        for(Artifact a : deps)
        {
            String id = a.getId();
            artifacts.put(id, a);
            File file = a.getFile();
            if (file != null)
            {
                checksums.put(id, calculateHash(file));
            } else {
                checksums.put(id,  "UNKNOWN");
            }
        }

        // ForkJoinPool.commonPool().submit(task);
        deps = project.getPluginArtifacts();
        for(Artifact a : deps)
        {
            String id = a.getId();
            artifacts.put(id, a);
            File file = a.getFile();
            if (file != null)
            {
                checksums.put(id, calculateHash(file));
            } else {
                checksums.put(id,  "UNKNOWN");
            }
        }

    }

    private String calculateHash(File file) throws IOException
    {
        InputStream in = new FileInputStream(file);
        try
        {
            byte[] buf = new byte[8*1024];
            int read;
            while((read = in.read(buf)) != -1)
            {
                digest.update(buf, 0, read);
            }
            return bytesToHex(digest.digest());
        } finally {
            digest.reset();
            silentClose(in);
        }
    }

    private void silentClose(InputStream in)
    {
        if (in != null)
        {
            try {
                in.close();
            } catch (Exception ignored) { /* ignored */ }
        }
    }

    private String bytesToHex(byte[] bytes)
    {
        return DatatypeConverter.printHexBinary(bytes);
    }

}



