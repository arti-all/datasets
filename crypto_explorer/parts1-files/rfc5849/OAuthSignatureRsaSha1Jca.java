/*
 * Copyright 2015 Jin Kwon &lt;jinahya_at_gmail.com&gt;.
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
package com.github.jinahya.rfc5849;

import java.security.PrivateKey;
import java.security.Signature;

/**
 * A request signer uses Java Cryptography Architecture.
 *
 * @author Jin Kwon &lt;jinahya_at_gmail.com&gt;
 * @see
 * <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
 * Cryptography Architecture (JCA) Reference Guide</a>
 */
public class OAuthSignatureRsaSha1Jca
        extends OAuthSignatureRsaSha1<PrivateKey> {

    /**
     * The algorithm name whose value is {@value #ALGORITHM}.
     */
    protected static final String ALGORITHM = "SHA1withRSA";

    @Override
    byte[] get(final PrivateKey initParam, final byte[] baseBytes)
            throws Exception {
        final Signature signature = Signature.getInstance(ALGORITHM);
        signature.initSign(initParam);
        signature.update(baseBytes);
        return signature.sign();
    }

    // -------------------------------------------------------------- baseString
    @Override
    public OAuthSignatureRsaSha1Jca baseString(
            final OAuthBaseString baseString) {
        return (OAuthSignatureRsaSha1Jca) super.baseString(baseString);
    }

    // --------------------------------------------------------------- initParam
    @Override
    public OAuthSignatureRsaSha1Jca initParam(final PrivateKey initParam) {
        return (OAuthSignatureRsaSha1Jca) super.initParam(initParam);
    }
}
