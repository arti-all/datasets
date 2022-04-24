/*
    The MIT License

    Copyright (c) 2014 Björn Raupach

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
*/
package org.rwds;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5 {
    
    private static final char[] hex = "0123456789abcdef".toCharArray();
    
    private MD5() {}
    
    public static String digest(String... args) {
        String digest = null;
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            for (String arg : args) {
                md5.update(arg.getBytes());
            }
            digest = toHex(md5.digest());
        } catch (NoSuchAlgorithmException ignore) {
            throw new RuntimeException(ignore);
        }
        return digest;
    }
    
    /* Source: http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java
     * Android does not have javax.xml.bind.DataTypeConverter which would
     * have been my favorite pick for the task.
     */
    private static String toHex(byte[] bytes) {
        char[] chars = new char[bytes.length << 1];
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i] & 0xFF;
            chars[i << 1] = hex[b >>> 4];
            chars[(i << 1) + 1] = hex[b & 0x0F];
        }
        return new String(chars);
    }
    
}
