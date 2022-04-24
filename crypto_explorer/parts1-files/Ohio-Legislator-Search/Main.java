package com.danklco.nopecincylegislators;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;

public class Main {

	static Pattern HOUSE_PATTERN = Pattern.compile("'http://www.ohiohouse.gov/.+'");
	static Pattern HOUSE_NAME_PATTERN = Pattern.compile("Representative .+<\\/a> \\([D|R]\\)<br \\/>District \\d+");
	static Pattern SENATE_PATTERN = Pattern.compile("'http://www.ohiosenate.gov/.+'");
	static Pattern SENATE_NAME_PATTERN = Pattern.compile("Senator .+<\\/a> \\([D|R]\\)<br \\/>District \\d+<br \\/>");

	public static void main(String[] args) throws IOException, KeyManagementException, NoSuchAlgorithmException {
		
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] certs, String authType) {
			}

			public void checkServerTrusted(X509Certificate[] certs, String authType) {
			}

		} };

		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

		// Create all-trusting host name verifier
		HostnameVerifier allHostsValid = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};
		// Install the all-trusting host verifier
		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

		String[] zipCodes = new String[] { "45213", "45215", "45227", "45236", "45237", "45241", "45242" };
		for (String zip : zipCodes) {
			System.out.println("Starting ZIP: " + zip);
			for (int i = 1; i < 8999; i++) {
				String plus4 = StringUtils.leftPad(String.valueOf(i), 4, '0');
				URL url = new URL("https://www.legislature.ohio.gov/legislators/find-my-legislators?zip=" + zip
						+ "&ext=" + plus4 + "&ch=Both");

				File f = new File("target/out.csv");
				URLConnection conn = null;
				InputStream in = null;
				try {
					System.out.println("Downloading ZIP: " + zip + " +4: " + plus4);
					conn = url.openConnection();
					in = conn.getInputStream();

					String page = IOUtils.toString(in);
					if (page.contains("The following representative(s) serves ZIP Code <strong><span>" + zip + " - "
							+ plus4 + "</span></strong>")) {

						Legislator house = new Legislator();
						Matcher houseMatcher = HOUSE_PATTERN.matcher(page);
						if (houseMatcher.find()) {
							house.url = houseMatcher.group(0).replace("'", "");
						}
						Matcher houseNameMatcher = HOUSE_NAME_PATTERN.matcher(page);
						if (houseNameMatcher.find()) {
							house.name = houseNameMatcher.group(0).replace("</a>", "").replace("<br />", " ").trim();
						}
						FileUtils.write(f, zip+"-"+plus4+","+house.name+","+house.url+"\n", true);

						Legislator senate = new Legislator();
						Matcher senateMatcher = SENATE_PATTERN.matcher(page);
						if (senateMatcher.find()) {
							senate.url = senateMatcher.group(0).replace("'", "");
						}
						Matcher senateNameMatcher = SENATE_NAME_PATTERN.matcher(page);
						if (senateNameMatcher.find()) {
							senate.name = senateNameMatcher.group(0).replace("</a>", "").replace("<br />", " ").trim();
						}
						System.out.println("Found Senate: " + senate + " house:" + house);

						FileUtils.write(f, zip+"-"+plus4+","+senate.name+","+senate.url+"\n", true);
					} else {
						System.out.println("Plus 4: " + plus4 + " not used");
					}
				} finally {
					IOUtils.closeQuietly(in);
					IOUtils.close(conn);
				}
			}

		}

	}

}

class Legislator {
	@Override
	public String toString() {
		return "Legislator [url=" + url + ", name=" + name + "]";
	}

	public String url = "";
	public String name = "";
}
