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

import java.security.Key;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * An implementation using the Java Cryptography Architecture.
 *
 * @author Jin Kwon &lt;jinahya_at_gmail.com&gt;
 * @see
 * <a href="http://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
 * Cryptography Architecture (JCA) Reference Guide</a>
 */
public class OAuthSignatureHmacSha1Jca extends OAuthSignatureHmacSha1 {

    /**
     * The algorithm name whose value is {@value #ALGORITHM}.
     */
    public static final String ALGORITHM = "HmacSHA1";

    @Override
    byte[] get(final byte[] keyBytes, final byte[] baseBytes) throws Exception {
        final Key key = new SecretKeySpec(keyBytes, ALGORITHM);
        final Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(key);
        final byte[] output = mac.doFinal(baseBytes);
        return output;
    }
}
