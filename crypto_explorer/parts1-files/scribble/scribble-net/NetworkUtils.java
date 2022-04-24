/*
 * Copyright 2015-2016 DevCon5 GmbH, info@devcon5.ch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.inkstand.scribble.net;

import static org.junit.Assume.assumeTrue;

import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Utility class for helping with network related tasks. The {@link NetworkUtils} provides methods to find
 * available TCP ports on the local machine and to check if a port is available. Both could help when writing
 * tests that require a tcp port and at the time of writing the test, it is unknown whether the port is available
 * on the build system, i.e. a CI server.
 * Created by Gerald M&uuml;cke on 11.03.2015.
 *
 * @author <a href="mailto:gerald.muecke@gmail.com">Gerald M&uuml;cke</a>
 */
public final class NetworkUtils {

    /**
     * The port offset may be configured at system level using the system property {@code scribble.net.portOffset}. The
     * offset defines the range of port-numbers used for random port search. The default range is 1024-65535. Any offset
     * will increase the lower bound, but not the upper. For example, setting a port offset of 10000 will result in a
     * range of 11024-65535. The port offset is an atomic integer value that is initialized using the system property
     * (default is 0). It may be set during runtime by setting the value of the port offset directly.
     */
    public static final AtomicInteger PORT_OFFSET = new AtomicInteger(Integer.parseInt(System.getProperty(
            "scribble.net.portOffset",
            "0")));
    /**
     * The default retry count specifies how many times the findAvailablePort method should try to find an
     * available port of no number of retries was specified. The default value can be configured using the
     * system property {@code scribble.net.maxRetries}. The default value is 3. It may be modified at runtime by
     * accessing the AtomicInteger directly.
     */
    public static final AtomicInteger RETRY_COUNT = new AtomicInteger(Integer.parseInt(System.getProperty(
            "scribble.net.maxRetries",
            "3")));
    //SCRIB-25 although it has no relevance regarding security using the secure random number generator will less
    //likely produce the same numbers in the same sequence of random numbers
    private static final Random RANDOM = new SecureRandom();

    private NetworkUtils() {

    }

    /**
     * Finds an available port. Maximum number of retries is 3 before an {@link org.junit.internal
     * .AssumptionViolatedException} is thrown.
     *
     * @return the number of the port that is available
     */
    public static int findAvailablePort() {

        return findAvailablePort(RETRY_COUNT.get());
    }

    /**
     * Finds an available port.
     *
     * @param maxRetries
     *         the maximum number of retries before an {@link org.junit.internal .AssumptionViolatedException} is
     *         thrown.
     *
     * @return the number of the port that is available
     */
    public static int findAvailablePort(int maxRetries) {

        int retries = 0;
        int randomPort;
        boolean portAvailable;
        do {
            randomPort = randomPort();
            portAvailable = isPortAvailable(randomPort);
            retries++;
        } while (retries <= maxRetries && !portAvailable);
        assumeTrue("no open port found", portAvailable);
        return randomPort;
    }

    /**
     * Creates a random port number above 1024.
     *
     * @return a tcp port number.
     */
    public static int randomPort() {

        final int offset = getPortOffset();
        return RANDOM.nextInt(65536 - offset) + offset;
    }

    /**
     * Checks if the specified is available as listen port.
     *
     * @param port
     *         the port to check
     *
     * @return true if the port is available
     */
    public static boolean isPortAvailable(final int port) {

        try (ServerSocket tcp = new ServerSocket(port);
            DatagramSocket udp = new DatagramSocket(port)) {
            return tcp.isBound() && udp.isBound();
        } catch (Exception e) { //NOSONAR
            return false;
        }
    }

    /**
     * The port offset is the range of ports that should not be used to find an open server port. The portrange is
     * always above 1024 to not collide with the standard ports below 1024. Further, the scribble system property for
     * defining an offset is applied. The default scribble offset is 0.
     *
     * @return the offset to apply for port search
     */
    static int getPortOffset() {

        return 1024 + PORT_OFFSET.get();
    }
}
