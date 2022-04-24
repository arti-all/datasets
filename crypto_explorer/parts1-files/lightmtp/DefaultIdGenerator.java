/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.ok2c.lightmtp.impl.protocol;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Formatter;
import java.util.Locale;

import com.ok2c.lightmtp.protocol.UniqueIdGenerator;
import com.ok2c.lightmtp.util.AddressUtils;

public class DefaultIdGenerator implements UniqueIdGenerator {

    private final String hostname;
    private final SecureRandom rnd;

    private long count;

    public DefaultIdGenerator() {
        super();
        this.hostname = AddressUtils.getLocalCanonicalHostName();
        try {
            this.rnd = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException ex) {
            throw new Error(ex);
        }
        this.rnd.setSeed(System.currentTimeMillis());
    }

    @Override
    public synchronized String generate() {
        StringBuilder buffer = new StringBuilder();
        Formatter formatter = new Formatter(buffer, Locale.US);
        formatter.format("%1$016x-%2x-%3x", System.currentTimeMillis(), this.rnd.nextInt(), ++this.count);
        buffer.append('@');
        buffer.append(this.hostname);
        return buffer.toString();
    }

}
