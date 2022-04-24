/*
 * Copyright 2012 Jin Kwon <jinahya at gmail.com>.
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
package com.github.jinahya.codec;

import static java.lang.Long.parseLong;
import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

/**
 * A class for encoding identifiers.
 *
 * @author Jin Kwon &lt;jinahya_at_gmail.com&gt;
 */
public class IdEncoder extends IdCodecBase<IdEncoder> {

    public static void main(final String... args) {
        try {
            final String encoded
                    = new IdEncoder().encodeUuid(UUID.fromString(args[0]));
            System.out.println(encoded);
            System.exit(0);
        } catch (final IllegalArgumentException iae) {
        } catch (final ArrayIndexOutOfBoundsException aioobe) {
        }
        try {
            final String encoded = new IdEncoder().encode(parseLong(args[0]));
            System.out.println(encoded);
            System.exit(0);
        } catch (final NumberFormatException nfe) {
        } catch (final ArrayIndexOutOfBoundsException aioobe) {
        }
        System.exit(1);
    }

//    @Override
//    public IdEncoder scale(final int scale) {
//        return super.scale(scale);
//    }
//
//    @Override
//    public IdEncoder radix(final int radix) {
//        return super.radix(radix);
//    }

    private String block(final long decoded) {
        final StringBuilder builder = new StringBuilder(Long.toString(decoded));
        final Random random = new SecureRandom();
        builder.ensureCapacity(builder.length() + getScale());
        for (int i = 0; i < getScale() - 1; i++) {
            builder.append(Integer.toString(random.nextInt(10)));
        }
        builder.append(Integer.toString(random.nextInt(9) + 1));
        builder.reverse();
        return Long.toString(Long.parseLong(builder.toString()), getRadix());
    }

    /**
     * Encodes given value.
     *
     * @param decoded the value to encode.
     * @return encoded output.
     */
    public String encode(final long decoded) {
        return block(decoded >>> Integer.SIZE) + "-"
               + block(decoded & 0xFFFFFFFFL);
    }

    /**
     * Encodes given value.
     *
     * @param decoded the value to encode
     * @return encoded output.
     */
    public String encodeUuid(final UUID decoded) {
        return encode(decoded.getMostSignificantBits()) + "-"
               + encode(decoded.getLeastSignificantBits());
    }
}
