package com.kade.apecricket.util;

import com.kade.apecricket.cache.CacheManager;

import java.security.MessageDigest;
import java.util.Map;

public class Utils {

    public static int getCountryId(String countryName) throws Exception {
        Map<Integer, String> countryMap = CacheManager.getCachedCountryMap();
        for (Map.Entry<Integer, String> entry : countryMap.entrySet()) {
            if (entry.getValue().equalsIgnoreCase(countryName)) {
                return entry.getKey();
            }
        }
        throw new Exception("Invalid country! '" + countryName + "' does not exist in the system.");
    }

    public static String getCountryNameById(int countryId) throws Exception {
        return CacheManager.getCachedCountryMap().get(countryId);
    }

    public static String encrypt(String x) throws Exception {
        MessageDigest md;
        md = java.security.MessageDigest.getInstance("SHA-1");
        md.reset();
        md.update(x.getBytes());
        return new String(md.digest());
    }

}
