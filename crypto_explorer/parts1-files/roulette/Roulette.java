package brown.roulette;

import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.SortedMap;
import java.util.TreeMap;
import org.apache.log4j.Logger;
import org.perf4j.StopWatch;

/**
 * @author Matt Brown
 * @date Jan 4, 2010
 */
public class Roulette {

	private static final Logger log = Logger.getLogger(Roulette.class);

	private static enum Color {
		BLACK,
		GREEN,
		RED
	}

	// The wheel is implemented as an array of Colors
	private Color[] wheel;

	private Random rand = new Random();

	private int numBlack;

	private int numRed;

	private int numGreen;

	public Roulette(int numBlack, int numRed, int numGreen) {

		this.numBlack = numBlack;
		this.numRed = numRed;
		this.numGreen = numGreen;

		this.wheel = new Color[numBlack + numRed + numGreen];

		// alternate black and red
		for (int i = 0; i < (numBlack + numRed); i++) {
			if (i % 2 == 0) {
				wheel[i] = Color.BLACK;
			}
			else {
				wheel[i] = Color.RED;
			}
		}
		// fill the remaining slots with green
		Arrays.fill(wheel, numBlack + numRed, wheel.length, Color.GREEN);
	}

	public Roulette(int numBlack, int numRed, int numGreen, Random random) {
		this(numBlack, numRed, numGreen);
		this.rand = random;
	}

	public int getNumOfSlots(Color c) {
		switch (c) {
			case BLACK:
				return numBlack;
			case GREEN:
				return numGreen;
			case RED:
				return numRed;
			default:
				throw new IllegalArgumentException("Unknown color");
		}
	}

	public int getSlots() {
		return this.wheel.length;
	}

	public void printWheel(PrintStream out) {
		for (int i = 0; i < wheel.length; i++) {
			out.printf("Slot %d: %s", Integer.valueOf(i + 1), wheel[i]);
		}
	}

	public Color spin() {
		int result = rand.nextInt(wheel.length);
		return wheel[result];
	}

	private final static int NUM_BLACK = 18;

	private final static int NUM_RED = 18;

	private final static int NUM_GREEN = 2;

	public static void main(String[] args) {

		int testRuns = 1000;
		if (args.length > 0) {
			try {
				testRuns = Integer.parseInt(args[0]);
			}
			catch (NumberFormatException e) {
				System.err.println("Not a valid input for number of attempts: " + args[0]);
			}

		}

		System.out.println("Tests using java.util.Random:\n");
		run(testRuns, new Roulette(NUM_BLACK, NUM_RED, NUM_GREEN));

		System.out.println("\n\nTests using java.security.SecureRandom:\n");
		run(testRuns, new Roulette(NUM_BLACK, NUM_RED, NUM_GREEN, new SecureRandom()));
	}

	private static void run(int testRuns, Roulette wheel) {
		List<Color> results = spinWheel(wheel, testRuns);

		countAndPrintStreaks(results);
	}

	private static List<Color> spinWheel(Roulette wheel, int testRuns) {
		StopWatch stopWatch = new StopWatch("spinning wheel");
		stopWatch.start();

		List<Color> results = new ArrayList<Color>(testRuns);
		for (long i = 0; i < testRuns; i++) {
			results.add(wheel.spin());
		}
		stopWatch.stop();

		// count results by color
		Map<Color, Integer> colorCount = new HashMap<Color, Integer>();
		for (Color col : Color.values()) {
			colorCount.put(col, 0);
		}
		for (Color col : results) {
			colorCount.put(col, colorCount.get(col) + 1);
		}

		System.out.printf("Spun wheel %d times (took %dms)\n\n", testRuns, stopWatch.getElapsedTime());

		for (Color col : Color.values()) {
			final Integer count = colorCount.get(col);
			final float colorPct = (float) wheel.getNumOfSlots(col) / wheel.getSlots();
			final float expected = colorPct * results.size();
			final float diff = Math.abs(expected - count.intValue());
			final float diffPct = diff / expected;
			System.out.printf("%-5s: %d times (expected %.3f, off by %.3f or %f%%)\n", col, count, expected, diff,
				diffPct);
		}
		System.out.println();

		return results;
	}

	private static void countAndPrintStreaks(List<Color> results) {

		StopWatch stopWatch = new StopWatch("counting streaks");
		stopWatch.start();

		Map<Integer, Integer> streaks = countStreaks(results);

		// wrap the map in a sortedMap and fill in any gaps for prettier output
		SortedMap<Integer, Integer> sortedStreaks = new TreeMap<Integer, Integer>(streaks);
		for (Integer i = 1; i < sortedStreaks.lastKey(); i++) {
			if (!sortedStreaks.containsKey(i)) {
				sortedStreaks.put(i, 0);
			}
		}

		stopWatch.stop();

		System.out.printf("Max of streak: %d (took %dms to count)\n", sortedStreaks.lastKey(), stopWatch
			.getElapsedTime());

		for (Map.Entry<Integer, Integer> entry : sortedStreaks.entrySet()) {
			System.out.printf("Streaks of length %2d: %5d\n", entry.getKey(), entry.getValue());
		}
	}

	private static Map<Integer, Integer> countStreaks(List<Color> results) {

		Map<Integer, Integer> streaks = new HashMap<Integer, Integer>(results.size());

		Color previousResult = results.get(0);
		int currentStreakLength = 1;
		for (int i = 1; i < results.size(); i++) {

			Color result = results.get(i);

			if (result == previousResult) {
				currentStreakLength++;
			}
			else {
				// streak broken
				incrementStreakCount(streaks, currentStreakLength);

				// reset
				currentStreakLength = 1;
			}

			previousResult = result;
		}

		return streaks;

	}

	private static void incrementStreakCount(Map<Integer, Integer> streaks, int streakLength) {
		final Integer key = Integer.valueOf(streakLength);
		if (!streaks.containsKey(key)) {
			streaks.put(key, 0);
		}
		streaks.put(key, streaks.get(streakLength) + 1);
	}
}
