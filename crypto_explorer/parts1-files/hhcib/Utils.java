package se.enbohms.hhcib.common;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Random;

import se.enbohms.hhcib.entity.Password;
import se.enbohms.hhcib.entity.Subject;

/**
 * Contains various util methods
 */
public final class Utils {

	private static final Random RANDOM = new SecureRandom();
	private static final String LETTERS = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ2345678";
	private static final int PASSWORD_LENGTH = 8;

	private static final int AFTER = 1;
	private static final int SAME_RATING = 0;
	private static final int BEFORE = -1;

	private Utils() {
		// Suppresses default constructor, ensuring non-instantiability.
	}

	/**
	 * 
	 * @param htmlString
	 * @return a string where all html-tags are removed
	 */
	public static final String removeHtmlFrom(String htmlString) {
		return htmlString.replaceAll("<br/>|<br />", " ")
				.replaceAll("\\<.*?\\>", "").replace("\r\n", " ");
	}

	/**
	 * Generates a {@link Password}
	 * 
	 * @return a 8 letters generated password
	 */
	public static Password generatePassword() {
		StringBuilder pwdBuilder = new StringBuilder();

		for (int i = 0; i < PASSWORD_LENGTH; i++) {
			int index = (int) (RANDOM.nextDouble() * LETTERS.length());
			pwdBuilder.append(LETTERS.substring(index, index + 1));
		}

		return Password.of(pwdBuilder.toString());
	}

	public static List<Subject> sortDesceding(List<Subject> subjects) {

		Collections.sort(subjects, new Comparator<Subject>() {

			@Override
			public int compare(Subject o1, Subject o2) {
				return o1.getRating() < o2.getRating() ? AFTER
						: o1.getRating() > o2.getRating() ? BEFORE : SAME_RATING;
			}
		});
		return subjects;
	}
}
