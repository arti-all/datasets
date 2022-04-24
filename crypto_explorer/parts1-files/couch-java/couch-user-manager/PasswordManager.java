/*******************************************************************************
 * Copyright 2011 John Casey
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package org.commonjava.auth.couch.data;

import static org.apache.commons.codec.digest.DigestUtils.sha512Hex;

import java.security.SecureRandom;

import javax.inject.Singleton;

@Singleton
public class PasswordManager
{

    private static final String ONETIME_PASSWORD_SEED =
        "23456789abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ-_!.";

    private static final int ONETIME_PASSWORD_LENGTH = 15;

    private final SecureRandom randomGenerator = new SecureRandom();

    public String generatePassword()
    {
        final StringBuilder sb = new StringBuilder();
        for ( int i = 0; i < ONETIME_PASSWORD_LENGTH; i++ )
        {
            final int idx = Math.abs( randomGenerator.nextInt() ) % ONETIME_PASSWORD_SEED.length();
            sb.append( ONETIME_PASSWORD_SEED.charAt( idx ) );
        }

        return sb.toString();
    }

    public boolean verifyPassword( final String digest, final String password )
    {
        return digest.equals( sha512Hex( password ) );
    }

    public String digestPassword( final String password )
    {
        return sha512Hex( password );
    }

}
