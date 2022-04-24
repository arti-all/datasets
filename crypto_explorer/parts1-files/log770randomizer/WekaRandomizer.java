package im.jeanfrancois.log770randomizer;

import org.kohsuke.args4j.Option;

import java.io.*;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Main logic for the weka randomizer
 *
 * @author jfim
 */
@SuppressWarnings({"FieldCanBeLocal"})
public class WekaRandomizer {
	@Option(name = "-input", usage = "Input Weka ARFF file", required = true)
	private File inputFile;

	@Option(name = "-outputDataLength", usage = "Number of data elements to put in a generated training file", required = true)
	private int outputDataCount;

	@Option(name = "-generatedFileCount", usage = "Number of training data files to generate")
	private int generatedFileCount = 1;

	@Option(name = "-outputPrefix", usage = "Prefix for output ARFF file(s)")
	private String outputPrefix = "output-";

	@Option(name = "-wekaClassifierArgs", usage = "Weka classifier arguments")
	private String wekaClassifierArgs;

	@Option(name = "-wekaOutputFilePrefix", usage = "Weka output file prefix")
	private String wekaOutputFilenamePrefix = "wekaout-";

	private Random random = new SecureRandom();

	/**
	 * Main randomizer logic
	 */
	public void run() {
		// Seed RNG
		random.setSeed(System.currentTimeMillis());

		System.out.println("Input file: " + inputFile.getAbsolutePath());
		System.out.println("Generating " + generatedFileCount + " ARFF file(s) with " + outputDataCount + " data element(s) in each");
		System.out.println();

		// Read the input data
		System.out.print("Reading input file... ");

		List<String> header = new ArrayList<String>();
		List<String> data = new ArrayList<String>();
		readInputFile(header, data);

		System.out.println("done");

		System.out.println("Read " + data.size() + " data elements");

		// Generate output files
		for (int fileNum = 0; fileNum < generatedFileCount; ++fileNum) {
			generateOutputFile(fileNum, header, data);
		}

		// Show the Weka command line args if wanted
		if(wekaClassifierArgs != null) {
			for (int fileNum = 0; fileNum < generatedFileCount; ++fileNum) {
			System.out.println("java " + wekaClassifierArgs + " -t " + new File(generateFileName(fileNum)).getAbsolutePath() + " > " + new File(wekaOutputFilenamePrefix + (fileNum + 1) + ".log").getAbsolutePath());
			}
		}
	}

	/**
	 * Generates a weka ARFF file.
	 *
	 * @param fileNum Number of generated file
	 * @param header  The header data
	 * @param data    The data that needs to be shuffled
	 */
	private void generateOutputFile(int fileNum, List<String> header, List<String> data) {
		try {
			String generatedFileName = generateFileName(fileNum);
			System.out.print("Generating output file " + generatedFileName + "... ");

			// Open the output file
			BufferedWriter writer = new BufferedWriter(new FileWriter(generatedFileName));

			// Write the header
			for (String headerLine : header) {
				writer.write(headerLine);
				writer.write("\n");
			}

			// Copy the data into a working buffer
			List<String> workingData = new ArrayList<String>(data);

			// For each data line to write
			for (int i = 0; i < outputDataCount; ++i) {
				// Pick a random element
				final int index = random.nextInt(workingData.size());
				String element = workingData.get(index);

				// Remove it
				workingData.remove(index);

				// Write it to the file
				writer.write(element);
				writer.write("\n");
			}

			// Close the file
			writer.close();

			System.out.println("done");
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	private String generateFileName(int fileNum) {
		return outputPrefix + (fileNum + 1) + ".arff";
	}

	/**
	 * Reads the input file into two lists of strings: the header and the actual weka data
	 *
	 * @param header The list of lines into which the header should be written
	 * @param data   The list of lines into which the data elements should be written
	 */
	private void readInputFile(List<String> header, List<String> data) {
		// Open the input file
		LineNumberReader reader = null;
		try {
			reader = new LineNumberReader(new BufferedReader(new FileReader(inputFile)));

			// Read all strings until "@data"
			String readLine = reader.readLine();
			while (readLine != null && !readLine.trim().matches(".*@data.*")) {
				header.add(readLine.trim());
				readLine = reader.readLine();
			}

			// Append the "@data" to the header
			if (readLine != null) {
				header.add(readLine.trim());
			}

			// Read all data elements
			readLine = reader.readLine();
			while (readLine != null) {
				final String trimmedLine = readLine.trim();

				if (trimmedLine.length() != 0)
					data.add(trimmedLine);

				readLine = reader.readLine();
			}
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			// Close the input file
			if (reader != null) {
				try {
					reader.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
}
