/*
   Copyright 2013 Red Hat, Inc. and/or its affiliates.

   This file is part of check-release plugin.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
package com.redhat.plugin.checkrelease;

import java.util.List;
import java.util.ArrayList;

import java.util.StringTokenizer;

import java.net.URL;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.BufferedInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;

import java.security.MessageDigest;

import org.apache.maven.artifact.Artifact;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;

import org.apache.maven.project.MavenProject;

import org.apache.maven.model.DistributionManagement;


/**
 * @author Burak Serdar (bserdar@redhat.com)
 */
public abstract class AbstractReleaseMojo extends AbstractMojo {    

    @Component
    protected MavenProject project;
    
    @Parameter(defaultValue="${project.artifact}",required=true,readonly=true)
    protected Artifact artifact;

    @Parameter(defaultValue="${project.packaging}",required=true,readonly=true)
    protected String packaging;
    
    @Parameter(defaultValue="${project.file}",required=true,readonly=true)
    protected File pomFile;

    @Parameter(defaultValue="${project.distributionManagement.repository.url}",required=true)
    protected String repoUrl;

    /**
     * If true, the project artifact is not deployed
     */ 
    @Parameter(defaultValue="false")
    protected boolean ignore;

    public void execute()
        throws MojoExecutionException, MojoFailureException {
        ComparatorFactory factory=new ComparatorFactory(getLog());
        List<ReleaseArtifact> releaseArtifacts=getReleaseArtifacts();
        if(releaseArtifacts!=null&&!releaseArtifacts.isEmpty()) {
            for(ReleaseArtifact a:releaseArtifacts) {
                getLog().info("Checking "+a);
                try {
                    String localHash=getFileHash(a.getFile());
                    String repoHash=retrieveHashFromRepo(a);
                    getLog().info("Hash retrieved from repo:"+repoHash);
                    getLog().info("Hash of the local file:"+localHash);
                    if(repoHash==null) {
                        getLog().info(a+" does not exist in the repository");
                    } else {
                        if(!repoHash.equals(localHash)) {
                            getLog().info(a+" hash doesn't match the hash in repo, comparing contents");
                            // Hashes don't match, try content comparison
                            FileComparator cmp=factory.getComparator(a.getFile().getName());
                            String repopath=a.getRepoDir()+"/"+a.getRepoFileName();
                            getLog().info("Retrieving artifact "+repopath);
                            URL u=new URL(repoUrl+"/"+repopath);
                            InputStream repoStream=getStreamForURL(u);
                            InputStream localStream=new FileInputStream(a.getFile());
                            String result=cmp.compare(localStream,repoStream);
                            if(result!=null) {
                                modifiedButSameVersion(a,result);
                            } else
                                modifiedButSemanticallyEqual(a);
                        } else {
                            identical(a);
                        }
                    }
                } catch (MojoExecutionException me) {
                    throw me;
                } catch (Exception e) {
                    throw new MojoExecutionException(e.toString());
                }
            }
        }
        end();
    }

    protected abstract void modifiedButSameVersion(ReleaseArtifact a,
                                                  String diff)
        throws MojoExecutionException, MojoFailureException;

    protected abstract void modifiedButSemanticallyEqual(ReleaseArtifact a)
        throws MojoExecutionException, MojoFailureException;

    protected abstract void identical(ReleaseArtifact a)
        throws MojoExecutionException, MojoFailureException;

    protected void end() {}

    protected String retrieveHashFromRepo(ReleaseArtifact a) 
        throws MojoExecutionException {
        String path=a.getRepoDir()+"/"+a.getRepoFileName()+".sha1";
        getLog().info("Retrieving hash "+path);
        try {
            URL u=new URL(repoUrl+"/"+path);
            InputStream stream=getStreamForURL(u);
            if(stream==null)
                return null;
            InputStreamReader rd=new InputStreamReader(stream);
            StringBuffer buf=new StringBuffer();
            int r;
            while((r=rd.read())!=-1) {
                char c=(char)r;
                if(Character.isDigit(c)||Character.isLetter(c))
                    buf.append(c);
            }
            stream.close();
            return buf.toString();
        } catch (MalformedURLException x) {
            throw new MojoExecutionException(x.getMessage());
        } catch (IOException io) {
            throw new MojoExecutionException(io.getMessage());
        }
    }
    
    protected InputStream getStreamForURL(URL u)
        throws MojoExecutionException {
        try {
            InputStream stream;
            if(u.getProtocol().equalsIgnoreCase("http")||
               u.getProtocol().equalsIgnoreCase("https")) {
                HttpURLConnection conn=(HttpURLConnection)u.openConnection();
                conn.setDoInput(true);
                conn.setRequestMethod("GET");
                stream=conn.getInputStream();
                getLog().debug("Response: "+conn.getResponseCode());
                if(conn.getResponseCode()!=HttpURLConnection.HTTP_OK)
                    return null;
            } else if(u.getProtocol().equalsIgnoreCase("file")) {
                stream=new FileInputStream(u.getPath());
            } else
                throw new MojoExecutionException("Unrecognized protocol:"+u.getProtocol());
            return stream;
        } catch (FileNotFoundException fnf) {
            return null;
        } catch (IOException io) {
            throw new MojoExecutionException(io.getMessage());
        }
    }


    protected List<ReleaseArtifact> getReleaseArtifacts() 
        throws MojoExecutionException {
        List<ReleaseArtifact> list=new ArrayList<ReleaseArtifact>();
        // Ignore maven plugins, they change at every build
        if(!packaging.equals("maven-plugin"))
            if(!ignore) {
                ReleaseArtifact a=new ReleaseArtifact();
                a.setGroup(artifact.getGroupId());
                a.setArtifactId(artifact.getArtifactId());
                a.setVersion(artifact.getVersion());
                a.setFile(pomFile);
                a.setPom(true);
                list.add(a);
                if(!"pom".equals(packaging)) {
                    a=new ReleaseArtifact();
                    a.setFile(artifact.getFile());
                    if(a.getFile()==null)
                        throw new MojoExecutionException("No artifact files for "+a);
                    a.setGroup(artifact.getGroupId());
                    a.setArtifactId(artifact.getArtifactId());
                    a.setVersion(artifact.getVersion());
                    a.setPom(false);
                    list.add(a);
                }
            }
        return list;        
    }
    

    protected static String getFileHash(File file) 
        throws MojoExecutionException  {
        try {
            MessageDigest md=MessageDigest.getInstance("SHA1");
            FileInputStream is=new FileInputStream(file);
            BufferedInputStream bis=new BufferedInputStream(is);
            int c;
            while((c=bis.read())!=-1)
                md.update((byte)c);
            bis.close();
            is.close();
            byte[] digest=md.digest();
            StringBuffer buf=new StringBuffer();
            for(int i=0;i<digest.length;i++) {
                int x=(digest[i]>>>4)&0x0F;
                buf.append((char)(x>9?(int)'a'+x-10:(int)'0'+x));
                x=digest[i]&0x000F;
                buf.append((char)(x>9?(int)'a'+x-10:(int)'0'+x));
            }
            return buf.toString();
        } catch (Exception e) {
            throw new MojoExecutionException("Cannot get hash for "+file.getPath(),e);
        }
    }        
}

