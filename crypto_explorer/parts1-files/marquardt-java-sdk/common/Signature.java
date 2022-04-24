/*
 * echocat Marquardt Java SDK, Copyright (c) 2015 echocat
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.echocat.marquardt.common.domain;

import org.echocat.marquardt.common.exceptions.SecurityMechanismException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Represents the signature with its mechanism / algorithm. Capable of producing a signature based on a byte[].
 * Capable of serializing the signature and its mechanism / algorithm into byte[] and writing it into an
 * OutputStream.
 *
 * Can also validate content if the signature is valid for a PublicKey.
 */
public class Signature extends BytesWithMechanism<Signature.Mechanism> {

    public enum Mechanism implements BytesWithMechanism.Mechanism {
        rsa("SHA1withRSA", Byte.MIN_VALUE, "SHA1withRSA");

        @Nonnull
        private final String _name;
        private final byte _code;
        @Nonnull
        private final String _javaAlgorithmName;

        Mechanism(@Nonnull final String name, final byte code, @Nonnull final String javaAlgorithmName) {
            _name = name;
            _code = code;
            _javaAlgorithmName = javaAlgorithmName;
        }

        @Nullable
        public static Mechanism findMechanism(final byte code) {
            for (final Mechanism candidate : values()) {
                if (code == candidate.getCode()) {
                    return candidate;
                }
            }
            return null;
        }

        @Nonnull
        public static Mechanism getMechanism(final byte code) {
            final Mechanism result = findMechanism(code);
            if (result == null) {
                throw new IllegalArgumentException("Unknown mechanism: #" + code);
            }
            return result;
        }

        @Nonnull
        @Override
        public String getName() {
            return _name;
        }

        @Override
        public byte getCode() {
            return _code;
        }

        @Nonnull
        public java.security.Signature createAlgorithm() throws NoSuchAlgorithmException {
           return java.security.Signature.getInstance(_javaAlgorithmName);
        }

        @Override
        public String toString() {
            return getName();
        }
    }

    private Signature(@Nonnull final Mechanism mechanism, @Nonnull final byte[] value) {
        super(mechanism, value);
    }

    public Signature(@Nonnull final byte[] content) {
        super(content);
    }

    @Override
    protected Mechanism codeToMechanism(final byte code) {
        return Mechanism.getMechanism(code);
    }

    /**
     * Validates if content is valid for this signature with a given PublicKey.
     *
     * @param content Content to validate
     * @param publicKey PublicKey used to validate signature.
     * @return true if the signature is valid, false if not.
     * @throws SecurityMechanismException When there are problems to set up
     * the validation with the given PublicKey or the this Signature.
     */
    public boolean isValidFor(@Nonnull final byte[] content, @Nonnull final PublicKey publicKey) {
        try {
            final java.security.Signature algorithm = getMechanism().createAlgorithm();
            algorithm.initVerify(publicKey);
            algorithm.update(content);
            return algorithm.verify(getValue());
        } catch (final GeneralSecurityException e) {
            throw new SecurityMechanismException("Could not check signature for content.", e);
        }
    }


    /**
     * Factory method that creates a Signature.
     *
     * @param content Content to produce Signature for.
     * @param privateKey PrivateKey to sign with.
     * @param with Mechanism to use for signing.
     * @return Signature that may be sent to clients and services to check if the content is from a trusted sender.
     * @throws SecurityMechanismException When there are problems setting up the signing with the given PrivateKey.
     */
    @Nonnull
    public static Signature createFor(@Nonnull final byte[] content, @Nonnull final PrivateKey privateKey, @Nonnull final Mechanism with) {
        try {
            final java.security.Signature algorithm = with.createAlgorithm();
            algorithm.initSign(privateKey);
            algorithm.update(content);
            return new Signature(with, algorithm.sign());
        } catch (final GeneralSecurityException e) {
            throw new SecurityMechanismException("Could not create signature for content.", e);
        }
    }

    @Override
    public String toString() {
        return "Signature signed with " + super.toString();
    }

}
