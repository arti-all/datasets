package com.saucelabs.grid;

import org.json.JSONException;
import org.json.JSONObject;
import org.openqa.selenium.Platform;
import org.openqa.selenium.remote.DesiredCapabilities;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Fran�ois Reynaud - Initial version of plugin
 * @author Ross Rowe - Additional functionalitye
 */
public class SauceOnDemandCapabilities implements Comparable {

    public static final String NAME = "selenium_name";
    public static final String SHORT_VERSION = "short_version";
    public static final String LONG_NAME = "long_name";
    public static final String LONG_VERSION = "long_version";
    public static final String PREFERRED_VERSION = "preferred_version";
    public static final String OS = "os";
    private static final String API_NAME = "api_name";

    private final Map<String, Object> map = new HashMap<String, Object>();
    private final JSONObject rawJSON;
    private final String md5;

    public SauceOnDemandCapabilities(String raw) throws JSONException {
        this.rawJSON = new JSONObject(raw);
        this.md5 = init();
    }

    public SauceOnDemandCapabilities(Map<String, ?> from) throws JSONException {
        DesiredCapabilities c = new DesiredCapabilities(from);
        this.rawJSON = new JSONObject(c.asMap());
        this.md5 = init();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((md5 == null) ? 0 : md5.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        SauceOnDemandCapabilities other = (SauceOnDemandCapabilities) obj;
        if (md5 == null) {
            if (other.md5 != null) return false;
        } else if (!md5.equals(other.md5)) return false;
        return true;
    }

    private String init() throws JSONException {
        StringBuilder b = new StringBuilder();
        b.append(copy(NAME));

        b.append(copy(SHORT_VERSION));
        b.append(copy(LONG_VERSION));
        b.append(copy(LONG_NAME));
        b.append(copy(PREFERRED_VERSION));
        b.append(copy(OS));

        String osName = (String) map.get(OS);
        //Sauce sends Windows 2012 which is WIN8
        if (osName.equalsIgnoreCase("windows 2012")) {
            set("platform", Platform.WIN8.toString());
        } else {
            set("platform", Platform.extractFromSysProperty(osName).toString());
        }
        String normalized = b.toString();
        String md5 = computeMD5(normalized);
        copy(API_NAME);
        set("browserName", (String) map.get(API_NAME));
        set("version", (String) map.get(SHORT_VERSION));

        return md5;
    }

    public String getName() {
        return get(NAME);
    }

    public String getShortVersion() {
        return get(SHORT_VERSION);
    }

    public String getLongName() {
        return get(LONG_NAME);
    }

    public String getLongVersion() {
        return get(LONG_VERSION);
    }

    public String getPreferredVersion() {
        return get(PREFERRED_VERSION);
    }

    public String getOs() {
        return get(OS);
    }

    @Override
    public String toString() {
        return getOs() + " " + getLongName() + " " + getLongVersion();
    }


    public Map<String, Object> asMap() {
        return map;
    }

    private String get(String key) {
        return (String) map.get(key);
    }

    private String copy(String key) throws JSONException {
        if (rawJSON.has(key)) {
            String value = rawJSON.getString(key);
            set(key, value);
            return key + value;
        } else {
            return "";
        }

    }

    private void set(String key, String value) {
        map.put(key, value);
    }

    private String computeMD5(String from) {
        try {
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.update(from.getBytes());
            byte[] md5sum = m.digest();
            BigInteger bigInt = new BigInteger(1, md5sum);
            String output = bigInt.toString(16);
            if (output.length() == 31) {
                output = "0" + output;
            }
            return output;
        } catch (NoSuchAlgorithmException ignore) {
            return null;
        }
    }

    public String getMD5() {
        return md5;
    }

    public int compareTo(Object o) {
        if (!(o instanceof SauceOnDemandCapabilities)) {
            throw new RuntimeException("cannot mix saucelab and not saucelab ones");
        } else {
            SauceOnDemandCapabilities other = (SauceOnDemandCapabilities) o;
            if (other.equals(this)) {
                return 0;
            }

            int compare = getOs().compareTo(other.getOs());
            if (compare != 0) {
                return compare;
            }
            compare = getLongName().compareTo(other.getLongName());
            if (compare != 0) {
                return compare;
            }
            DecimalFormat d = new DecimalFormat("0.0");
            try {
                String version = getShortVersion();
                String otherShortVersion1 = other.getShortVersion();
                if (isNumeric(version) && isNumeric(otherShortVersion1)) {
                    Number shortVersion = d.parse(version);
                    Number otherShortVersion = d.parse(otherShortVersion1);
                    return new Integer(shortVersion.intValue()).compareTo(new Integer(otherShortVersion.intValue()));
                } else {
                    return version.compareTo(otherShortVersion1);
                }
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }
        return 0;
    }

    private static boolean isNumeric(String str) {
        return str.matches("\\d+(\\.\\d+)?");
    }
}
