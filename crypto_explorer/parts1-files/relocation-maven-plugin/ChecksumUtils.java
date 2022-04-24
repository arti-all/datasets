package org.carlspring.maven.util;

/**
 * Copyright 2012 Martin Todorov.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author mtodorov
 */
public class ChecksumUtils
{

    public static final String DIGEST_TYPE_MD5 = "MD5";
    public static final String DIGEST_TYPE_SHA1 = "SHA1";


    public static byte[] createDigest(String filename, String digestType)
            throws IOException, NoSuchAlgorithmException
    {
        return createDigest(new File(filename), digestType);
    }

    public static byte[] createDigest(File file, String digestType)
            throws IOException, NoSuchAlgorithmException
    {
        InputStream fis = null;

        MessageDigest complete;
        try
        {
            fis = new FileInputStream(file);

            byte[] buffer = new byte[1024];
            complete = MessageDigest.getInstance(digestType);
            int numRead;

            do
            {
                numRead = fis.read(buffer);
                if (numRead > 0)
                {
                    complete.update(buffer, 0, numRead);
                }
            }
            while (numRead != -1);

        }
        finally
        {
            if (fis != null)
            {
                fis.close();
            }
        }

        return complete.digest();
    }

    public static String getChecksum(String filename, String digestType)
            throws IOException, NoSuchAlgorithmException
    {
        return getChecksum(new File(filename).getAbsoluteFile(), digestType);
    }

    public static String getChecksum(File file, String digestType)
            throws IOException, NoSuchAlgorithmException
    {
        byte[] b = createDigest(file, digestType);
        String result = "";

        for (byte aB : b)
        {
            result += Integer.toString((aB & 0xff) + 0x100, 16).substring(1);
        }

        return result;
    }

    public static String getMD5Checksum(File file)
            throws IOException, NoSuchAlgorithmException
    {
        return getChecksum(file, DIGEST_TYPE_MD5);
    }

    public static String getMD5Checksum(String filename)
            throws IOException, NoSuchAlgorithmException
    {
        return getChecksum(filename, DIGEST_TYPE_MD5);
    }

    public static String getSHA1Checksum(String filename)
            throws IOException, NoSuchAlgorithmException
    {
        return getChecksum(filename, DIGEST_TYPE_SHA1);
    }

    public static void generateMD5ChecksumFile(String filename)
            throws IOException, NoSuchAlgorithmException
    {
        generateMD5ChecksumFile(new File(filename).getAbsoluteFile());
    }

    public static void generateMD5ChecksumFile(File file)
            throws IOException, NoSuchAlgorithmException
    {
        writeChecksumToFile(file.getAbsolutePath()+ ".md5", getMD5Checksum(file.getAbsolutePath()));
    }

    public static void generateSHA1ChecksumFile(String filename)
            throws IOException, NoSuchAlgorithmException
    {
        generateSHA1ChecksumFile(new File(filename).getAbsoluteFile());
    }

    public static void generateSHA1ChecksumFile(File file)
            throws IOException, NoSuchAlgorithmException
    {
        writeChecksumToFile(file.getAbsolutePath()+ ".sha1", getSHA1Checksum(file.getAbsolutePath()));
    }

    private static void writeChecksumToFile(String filename, String checksum)
            throws IOException
    {
        writeChecksumToFile(new File(filename).getAbsoluteFile(), checksum);
    }

    private static void writeChecksumToFile(File file, String checksum)
            throws IOException
    {
        OutputStream fos = null;

        try
        {
            System.out.println(file.getAbsolutePath());

            if (file.getAbsoluteFile().exists())
            {
                System.out.println("Deleting " + file.getAbsolutePath());
                //noinspection ResultOfMethodCallIgnored
                file.delete();
            }

            fos = new FileOutputStream(file);
            fos.write((checksum + "\n").getBytes());
            fos.flush();
        }
        finally
        {
            if (fos != null)
                fos.close();
        }
    }

}
