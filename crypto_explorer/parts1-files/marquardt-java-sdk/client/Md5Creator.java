/*
 * echocat Marquardt Java SDK, Copyright (c) 2015 echocat
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.echocat.marquardt.client.util;

import org.echocat.marquardt.common.exceptions.SecurityMechanismException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Creates MD5 hashes of byte streams.
 */
public final class Md5Creator {

    static final Md5Creator INSTANCE = new Md5Creator();

    private Md5Creator() {
    }

    /**
     * Creates MD5 hash of a given byte stream.
     *
     * @param input input byte array to create the MD5 hash for
     * @return MD5 hash of the byte array
     */
    public static byte[] create(final byte[] input) {
        return INSTANCE.getMessageDigest("MD5").digest(input);
    }

    MessageDigest getMessageDigest(final String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new SecurityMechanismException("Cannot produce MD5. Algorithm not present.", e);
        }
    }

}
