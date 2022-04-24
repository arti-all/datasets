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

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;

public class StringUtilities {
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s");
    private static char[] randomStringCharacters = new char[]{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
            'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

    public static String generateRandomString(final int length) {
        final StringBuilder text = new StringBuilder();

        try {
            final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");

            for (int i = 0; i < length; i++) {
                text.append(randomStringCharacters[random.nextInt(randomStringCharacters.length)]);
            }
        } catch (final Exception ex) {
            return null;
        }

        return text.toString();
    }

    public static int rtrimCount(final String input) {
        if (input == null) return 0;
        if (input.isEmpty()) return 0;
        int i = input.length() - 1;
        while (i >= 0 && input.charAt(i) == ' ') --i;
        return input.length() - i;
    }

    public static int ltrimCount(final String input) {
        if (input == null) return 0;
        if (input.isEmpty()) return 0;
        int i = 0;
        while (i < input.length() && input.charAt(i) == ' ') ++i;
        return i;
    }

    public static String rtrim(final String input) {
        if (input == null) return null;
        if (input.isEmpty()) return input;
        int i = input.length() - 1;
        while (i >= 0 && input.charAt(i) == ' ') --i;
        return input.substring(0, i + 1);
    }

    public static String ltrim(final String input) {
        if (input == null) return null;
        if (input.isEmpty()) return input;
        int i = 0;
        while (i < input.length() && input.charAt(i) == ' ') ++i;
        return input.substring(i, input.length());
    }

    public static String cleanTextForCSV(final String input) {
        if (input == null) return "";

        return "\"" + input.replaceAll("\"", "\"\"") + "\"";
    }

    public static String uncapitaliseFirstCharacter(final String input) {
        if (input == null) return null;

        if (input.isEmpty()) return "";

        final String firstChar = input.substring(0, 1).toLowerCase();
        final String remaining = input.length() > 1 ? input.substring(1) : "";

        return firstChar + remaining;
    }

    /**
     * @param input The original string
     * @return A string with special characters that break Publican stripped out
     */
    public static String cleanTextForXML(final String input) {
        return input.replaceAll("(\\u00C2)|(\\u00A0)", "&nbsp;")        // non breaking space (UTF-8)
                .replaceAll("\\u00A0", "&nbsp;")            // non breaking space (ISO-8859-1 or US-ASCII)
                .replaceAll("\\u00E9", "\u00C3\u00A9")        // a lower case Latin e with acute
                .replaceAll("(\\u2018)|(\\u2019)", "&apos;")        // left/right single quote
                .replaceAll("(\\u201C)|(\\u201D)", "&quot;")        // right/left double quote
                .replaceAll("�", "-");                        // a long dash
    }

    /**
     * Prepares a string to be inserted into xml by escaping any reserved XML symbols.
     * <p/>
     * The current symbols are: < > & " '
     *
     * @param input The original string
     * @return A string with the reserved xml characters escaped.
     */
    public static String escapeForXML(final String input) {
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    /**
     * Prepares a string to be inserted into xml entity declaration by escaping any reserved XML symbols.
     * <p/>
     * The current symbols are: < > & "' %
     *
     * @param input The original string
     * @return A string with the reserved xml characters escaped.
     */
    public static String escapeForXMLEntity(final String input) {
        return escapeForXML(input).replace("%", "&percnt;");
    }

    /**
     * A utility function to allow us to build a single string with line breaks
     * from an array of strings. This is really just used to make defining text
     * files in code easier to read, as opposed to having to add and maintain
     * line breaks in the initial string definition.
     */
    public static String buildString(final String[] lines) {
        return buildString(lines, "\n");
    }

    public static String buildString(final String[] lines, final String separator) {
        final StringBuilder retValue = new StringBuilder();
        for (final String line : lines) {
            if (retValue.length() != 0) retValue.append(separator);
            retValue.append(line);
        }

        return retValue.toString();
    }

    public static boolean startsWithWhitespace(final String input) {
        if (input == null || input.isEmpty()) return false;

        /* find any matches */
        final Matcher whitespaceMatcher = WHITESPACE_PATTERN.matcher(input.substring(0, 1));

        /* loop over the regular expression matches */
        return whitespaceMatcher.find();

    }

    public static boolean endsWithWhitespace(final String input) {
        if (input == null || input.isEmpty()) return false;

        /* find any matches */
        final Matcher whitespaceMatcher = WHITESPACE_PATTERN.matcher(input.substring(input.length() - 1, input.length()));

        /* loop over the regular expression matches */
        return whitespaceMatcher.find();
    }

    public static String convertToLinuxLineEndings(final String input) {
        if (input == null) return "";
        return input.replaceAll("\\r", "");
    }

    public static String convertToWindowsLineEndings(final String input) {
        if (input == null) return "";
        return input.replaceAll("(?<!\\r)\\n", "\\r\\n");
    }

    /**
     * Converts a String into bytes using UTF-8 encoding.
     *
     * @param input The String to convert
     * @return The byte array from the input String, or null if the input is null
     */
    public static byte[] getStringBytes(final String input) {
        try {
            return input == null ? new byte[]{} : input.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            // UTF-8 is a valid format so this should exception should never get thrown
        }

        return new byte[]{};
    }

    /**
     * Gets the first index of a character ignoring characters that have been escaped
     *
     * @param input The string to be searched
     * @param delim The character to be found
     * @return The index of the found character or -1 if the character wasn't found
     */
    public static int indexOf(final String input, final char delim) {
        return indexOf(input, delim, 0);
    }

    /**
     * Gets the first index of a character after fromIndex. Ignoring characters that have been escaped
     *
     * @param input     The string to be searched
     * @param delim     The character to be found
     * @param fromIndex Start searching from this index
     * @return The index of the found character or -1 if the character wasn't found
     */
    public static int indexOf(final String input, final char delim, final int fromIndex) {
        if (input == null) return -1;
        int index = input.indexOf(delim, fromIndex);
        if (index != 0) {
            while (index != -1 && index != (input.length() - 1)) {
                if (input.charAt(index - 1) != '\\') break;
                index = input.indexOf(delim, index + 1);
            }
        }
        return index;
    }

    /**
     * Gets the last index of a character ignoring characters that have been escaped
     *
     * @param input The string to be searched
     * @param delim The character to be found
     * @return The index of the found character or -1 if the character wasn't found
     */
    public static int lastIndexOf(final String input, final char delim) {
        return input == null ? -1 : lastIndexOf(input, delim, input.length());
    }

    /**
     * Gets the last index of a character starting at fromIndex. Ignoring characters that have been escaped
     *
     * @param input     The string to be searched
     * @param delim     The character to be found
     * @param fromIndex Start searching from this index
     * @return The index of the found character or -1 if the character wasn't found
     */
    public static int lastIndexOf(final String input, final char delim, final int fromIndex) {
        if (input == null) return -1;
        int index = input.lastIndexOf(delim, fromIndex);
        while (index != -1 && index != 0) {
            if (input.charAt(index - 1) != '\\') break;
            index = input.lastIndexOf(delim, index - 1);
        }
        return index;
    }

    /**
     * Similar to the normal String split function. However this function ignores escaped characters (i.e. \[ ).
     *
     * @param input The string to be split
     * @param split The char to be used to split the input string
     * @return An array of split strings
     */
    public static String[] split(final String input, final char split) {
        int index = indexOf(input, split);
        int prevIndex = 0;
        final ArrayList<String> output = new ArrayList<String>();
        if (index == -1) {
            output.add(input);
            return output.toArray(new String[1]);
        }
        while (index != -1) {
            output.add(input.substring(prevIndex, index));
            prevIndex = index + 1;
            index = indexOf(input, split, index + 1);
        }
        output.add(input.substring(prevIndex, input.length()));
        return output.toArray(new String[output.size()]);
    }

    /**
     * Similar to the normal String split function. However this function ignores escaped characters (i.e. \[ ).
     *
     * @param input The string to be split
     * @param split The char to be used to split the input string
     * @param limit The maximum number of times to split the string
     * @return An array of split strings
     */
    public static String[] split(final String input, final char split, final int limit) {
        int index = indexOf(input, split);
        int prevIndex = 0, count = 1;
        final ArrayList<String> output = new ArrayList<String>();
        if (index == -1) {
            output.add(input);
            return output.toArray(new String[1]);
        }
        while (index != -1 && count != limit) {
            output.add(input.substring(prevIndex, index));
            prevIndex = index + 1;
            index = indexOf(input, split, index + 1);
            count++;
        }
        output.add(input.substring(prevIndex, input.length()));
        return output.toArray(new String[output.size()]);
    }

    /**
     * Checks to see if a string entered is alpha numeric
     *
     * @param input The string to be tested
     * @return True if the string is alpha numeric otherwise false
     */
    public static boolean isAlphanumeric(final String input) {
        for (int i = 0; i < input.length(); i++) {
            if (!Character.isLetterOrDigit(input.charAt(i))) return false;
        }
        return true;
    }

    /**
     * Checks a string to see if it has the UTF8 replacement character
     *
     * @param input The string to be checked
     * @return True of the replacement character is found otherwise false
     */
    public static boolean hasInvalidUTF8Character(final String input) {
        for (char c : input.toCharArray()) {
            if (c == 0xFFFD) return true;
        }
        return false;
    }

    /**
     * Converts a string so that it can be used in a regular expression.
     *
     * @param input The string to be converted.
     * @return An escaped string that can be used in a regular expression.
     */
    public static String convertToRegexString(final String input) {
        return input.replaceAll("\\\\", "\\\\").replaceAll("\\*", "\\*").replaceAll("\\+", "\\+").replaceAll("\\]", "\\]").replaceAll("\\[",
                "\\[").replaceAll("\\(", "\\(").replaceAll("\\)", "\\)").replaceAll("\\?", "\\?").replaceAll("\\$", "\\$").replaceAll("\\|",
                "\\|").replaceAll("\\^", "\\^").replaceAll("\\.", "\\.");
    }

    /**
     * Checks to see how similar two strings are using the Levenshtein distance algorithm.
     *
     * @param s1 The first string to compare against.
     * @param s2 The second string to compare against.
     * @return A value between 0 and 1.0, where 1.0 is an exact match and 0 is no match at all.
     */
    public static double similarLevenshtein(String s1, String s2) {
        if (s1.equals(s2)) {
            return 1.0;
        }

        // Make sure s1 is the longest string
        if (s1.length() < s2.length()) {
            String swap = s1;
            s1 = s2;
            s2 = swap;
        }

        int bigLength = s1.length();
        return (bigLength - StringUtils.getLevenshteinDistance(s2, s1)) / (double) bigLength;
    }

    /**
     * Checks to see how similar two strings are using the Damerau-Levenshtein distance algorithm.
     *
     * @param s1 The first string to compare against.
     * @param s2 The second string to compare against.
     * @return A value between 0 and 1.0, where 1.0 is an exact match and 0 is no match at all.
     */
    public static double similarDamerauLevenshtein(String s1, String s2) {
        if (s1.equals(s2)) {
            return 1.0;
        }

        // Make sure s1 is the longest string
        if (s1.length() < s2.length()) {
            String swap = s1;
            s1 = s2;
            s2 = swap;
        }

        int bigLength = s1.length();
        return (bigLength - getDamerauLevenshteinDistance(s2, s1)) / (double) bigLength;
    }

    /**
     * Get the minimum number of operations required to get from one string to another using the Damerau-Levenshtein distance algorithm
     * <p/>
     * Note: Java implementation of the C# algorithm from https://en.wikipedia.org/wiki/Damerau%E2%80%93Levenshtein_distance
     *
     * @param source The source string.
     * @param target The string to transform the source into.
     * @return The number of operations required to transform source into target.
     */
    public static int getDamerauLevenshteinDistance(String source, String target) {
        if (source == null || source.isEmpty()) {
            if (target == null || target.isEmpty()) {
                return 0;
            } else {
                return target.length();
            }
        } else if (target == null || target.isEmpty()) {
            return source.length();
        }

        int[][] score = new int[source.length() + 2][target.length() + 2];

        int INF = source.length() + target.length();
        score[0][0] = INF;
        for (int i = 0; i <= source.length(); i++) {
            score[i + 1][1] = i;
            score[i + 1][0] = INF;
        }
        for (int j = 0; j <= target.length(); j++) {
            score[1][j + 1] = j;
            score[0][j + 1] = INF;
        }

        final SortedMap<Character, Integer> sd = new TreeMap<Character, Integer>();
        for (final char letter : (source + target).toCharArray()) {
            if (!sd.containsKey(letter)) sd.put(letter, 0);
        }

        for (int i = 1; i <= source.length(); i++) {
            int DB = 0;
            for (int j = 1; j <= target.length(); j++) {
                int i1 = sd.get(target.charAt(j - 1));
                int j1 = DB;

                if (source.charAt(i - 1) == target.charAt(j - 1)) {
                    score[i + 1][j + 1] = score[i][j];
                    DB = j;
                } else {
                    score[i + 1][j + 1] = Math.min(score[i][j], Math.min(score[i + 1][j], score[i][j + 1])) + 1;
                }

                score[i + 1][j + 1] = Math.min(score[i + 1][j + 1], score[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1));
            }

            sd.put(source.charAt(i - 1), i);
        }

        return score[source.length() + 1][target.length() + 1];
    }

    /**
     * Test to see if a String is null or contains only whitespace.
     *
     * @param input The String to test
     * @return true if input is null or contains only whitespace, and false otherwise
     */
    public static boolean isStringNullOrEmpty(final String input) {
        if (input == null || input.trim().isEmpty()) {
            return true;
        }
        return false;

    }
}