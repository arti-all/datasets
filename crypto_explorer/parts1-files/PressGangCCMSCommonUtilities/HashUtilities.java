/*
  Copyright 2011-2014 Red Hat, Inc

  This file is part of PressGang CCMS.

  PressGang CCMS is free software: you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  PressGang CCMS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with PressGang CCMS.  If not, see <http://www.gnu.org/licenses/>.
*/

package org.jboss.pressgang.ccms.utils.common;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A collection of static methods for working with has codes.
 *
 * @author Matthew Casperson
 */
public class HashUtilities {
    private final static Logger LOG = LoggerFactory.getLogger(HashUtilities.class);

    /**
     * Generates a MD5 Hash for a specific string
     *
     * @param input The string to be converted into an MD5 hash.
     * @return The MD5 Hash string of the input string.
     */
    public static String generateMD5(final String input) {
        try {
            return generateMD5(input.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            LOG.debug("An error occurred generating the MD5 Hash of the input string", e);
            return null;
        }
    }

    /**
     * Generates a MD5 Hash for a specific byte[]
     *
     * @param input The byte[] to be converted into an MD5 hash.
     * @return The MD5 Hash string of the input string.
     */
    public static String generateMD5(final byte[] input) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.reset();
            byte[] digest = messageDigest.digest(input);
            return new String(Hex.encodeHex(digest));
        } catch (Exception e) {
            LOG.debug("An error occurred generating the MD5 Hash of the input string", e);
            return null;
        }
    }

    /**
     * Generates a SHA-1 Hash for a specific string
     *
     * @param input The string to be converted into an SHA-1 hash.
     * @return The SHA-1 Hash string of the input string.
     */
    public static String generateSHA1(final String input) {
        try {
            return generateSHA1(input.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            LOG.debug("An error occurred generating the SHA-1 Hash of the input string", e);
            return null;
        }
    }

    /**
     * Generates a SHA-1 Hash for a specific byte[]
     *
     * @param input The byte[] to be converted into an SHA-1 hash.
     * @return The SHA-1 Hash string of the input string.
     */
    public static String generateSHA1(final byte[] input) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            messageDigest.reset();
            byte[] digest = messageDigest.digest(input);
            return new String(Hex.encodeHex(digest));
        } catch (Exception e) {
            LOG.debug("An error occurred generating the SHA-1 Hash of the input string", e);
            return null;
        }
    }

    /**
     * Generates a SHA-256 Hash for a specific string
     *
     * @param input The string to be converted into an SHA-1 hash.
     * @return The SHA-256 Hash string of the input string.
     */
    public static String generateSHA256(final String input) {
        try {
            return generateSHA256(input.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            // This shouldn't happen
            LOG.debug("An error occurred generating the SHA-256 Hash of the input byte[]", e);
            return null;
        }
    }

    /**
     * Generates a SHA-256 Hash for a specific byte[]
     *
     * @param input The byte[] to be converted into an SHA-1 hash.
     * @return The SHA-256 Hash string of the input string.
     */
    public static String generateSHA256(final byte[] input) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.reset();
            byte[] digest = messageDigest.digest(input);
            return new String(Hex.encodeHex(digest));
        } catch (Exception e) {
            LOG.debug("An error occurred generating the SHA-256 Hash of the input byte[]", e);
            return null;
        }
    }
}
