/*
 * Copyright 2015 Jin Kwon &lt;jinahya at gmail.com&gt;.
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

import static com.github.jinahya.rfc5849._Percent.encodePercent;
import java.security.SecureRandom;
import java.util.Random;

/**
 * A simple nonce generator.
 *
 * @author Jin Kwon &lt;jinahya at gmail.com&gt;
 * @see <a href="https://tools.ietf.org/html/rfc5849#section-3.3">3.3. Nonce and
 * Timestamp (RFC 5849)</a>
 */
public class SimpleOAuthNonce implements OAuthNonce {

    /**
     * Creates a new instance which generates nonce values with given
     * identifiers as a prefix.
     *
     * @param identifiers identifies for specifying client such as device or
     * agent identifier.
     * @return a nonce builder
     */
    @Deprecated
    public static OAuthNonce of(final String... identifiers) {
        final StringBuilder builder = new StringBuilder();
        for (final String identifier : identifiers) {
            builder.append(encodePercent(String.valueOf(identifier)))
                    .append("-");
        }
        final String prefix = builder.toString();
        return new SimpleOAuthNonce() {
            @Override
            public String get() {
                return prefix + super.get();
            }
        };
    }

    /**
     * {@inheritDoc} This methods returns the value of {@link Random#nextLong()}
     * invoked on what {@link #random()} returns.
     *
     * @return {@inheritDoc}
     */
    @Override
    public String get() {
        return Long.toString(random().nextLong());
    }

    /**
     * Returns a random.
     *
     * @return a random
     */
    protected Random random() {
        if (random == null) {
            random = new SecureRandom();
        }
        return random;
    }

    private Random random;
}
