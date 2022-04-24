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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URL;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InetUtilities {
    private static final Logger LOG = LoggerFactory.getLogger(InetUtilities.class);

    /**
     * Downloads a file as a byte array
     *
     * @param url The URL of the resource to download
     * @return The byte array containing the data of the downloaded file
     */
    public static byte[] getURLData(final String url) {
        final int readBytes = 1000;

        URL u;
        InputStream is = null;
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        // See http://www.exampledepot.com/egs/javax.net.ssl/TrustAll.html

        // Create a trust manager that does not validate certificate chains
        final TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
            }
        }};

        // Install the all-trusting trust manager
        // FIXME from Lee: This doesn't seem like a wise idea to install an all-trusting cert manager by default
        try {
            final SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (final Exception ex) {
            LOG.error("Unable to install the all-trust SSL Manager", ex);
        }

        try {
            u = new URL(url);
            is = u.openStream(); // throws an IOException

            int nRead;
            byte[] data = new byte[readBytes];

            while ((nRead = is.read(data, 0, readBytes)) != -1) {
                buffer.write(data, 0, nRead);
            }
        } catch (final Exception ex) {
            LOG.error("Unable to read data from URL", ex);
        } finally {
            try {
                buffer.flush();

                if (is != null) is.close();
            } catch (final Exception ex) {
                LOG.error("Unable to flush and close URL Input Stream", ex);
            }
        }

        return buffer.toByteArray();
    }
}
