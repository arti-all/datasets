package io.tesla.sra;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.codehaus.plexus.util.FileUtils;

import com.google.common.io.ByteStreams;

public class SourceReleaseAnalyzer {

  private String groupId;
  private String artifactId;
  private String version;
  private String stagingUrl;
  private File temp;

  public SourceReleaseAnalyzer(String groupId, String artifactId, String version, String stagingUrl) {
    this.groupId = groupId;
    this.artifactId = artifactId;
    this.version = version;
    this.stagingUrl = stagingUrl;
    this.temp = new File("/tmp/test");
  }

  public void sebbalize() throws IOException {
    //
    // stagingUrl: https://repository.apache.org/content/repositories/maven-065
    //    groupId: org.apache.maven
    // artifactId: apache-maven
    //    version: 3.1.1
    //
    // https://repository.apache.org/content/repositories/maven-065/org/apache/maven/apache-maven/3.1.1/apache-maven-3.1.1-src.zip"
    // https://repository.apache.org/content/repositories/maven-065/org/apache/maven/apache-maven/3.1.1/apache-maven-3.1.1-src.zip.sha1"
    // https://repository.apache.org/content/repositories/maven-065/org/apache/maven/apache-maven/3.1.1/apache-maven-3.1.1-bin.zip"
    // https://repository.apache.org/content/repositories/maven-065/org/apache/maven/apache-maven/3.1.1/apache-maven-3.1.1-bin.zip.sha1"
    //

    if (stagingUrl.endsWith("/")) {
      stagingUrl = stagingUrl.substring(0, stagingUrl.length() - 1);
    }

    String groupIdPath = groupId.replace('.', '/');
    String baseUrl = String.format("%s/%s/%s/%s/%s-%s", stagingUrl, groupIdPath, artifactId, version, artifactId, version);

    String sourceZipUrl = String.format("%s-%s", baseUrl, "src.zip");
    String sourceZipSha1Url = String.format("%s-%s", baseUrl, "src.zip.sha1");
    String binZipUrl = String.format("%s-%s", baseUrl, "bin.zip");
    String binZipSha1Url = String.format("%s-%s", baseUrl, "bin.zip.sha1");

    System.out.println("Analyzer...");
    System.out.println();
    System.out.println("stagingUrl: " + stagingUrl);
    System.out.println("groupId: " + groupId);
    System.out.println("artifactId: " + artifactId);
    System.out.println("version: " + version);
    System.out.println();

    //
    // Make sure all the URLs exist
    //
    if (urlExists(sourceZipUrl)) {
      System.out.println("Source ZIP url exists.");
      System.out.println(sourceZipUrl);
      System.out.println();
    }

    if (urlExists(sourceZipSha1Url)) {
      System.out.println("Source ZIP SHA1 url exists.");
      System.out.println(sourceZipSha1Url);
      System.out.println();
    }

    if (urlExists(binZipUrl)) {
      System.out.println("Binary ZIP url exists.");
      System.out.println(binZipUrl);
      System.out.println();
    }

    if (urlExists(binZipSha1Url)) {
      System.out.println("Binary ZIP SHA1 url exists.");
      System.out.println(binZipSha1Url);
      System.out.println();
    }

    //
    // Get the files
    // Validate the SHA1s
    // Pull the source release SHA1 out of the binary
    // Check out the sha1 source code
    // Unpack the source release
    // Compare and make sure all files in the source archive are present in the checkout
    //
    File sourceZip = get(sourceZipUrl);
    String calculatedSourceZipSha1 = sha1(sourceZip);
    String sourceZipSha1 = FileUtils.fileRead(get(sourceZipSha1Url));
    if (calculatedSourceZipSha1.equals(sourceZipSha1)) {
      System.out.println("Calculated SHA1 of source ZIP matches published SHA1 of source ZIP.");
      System.out.println(sourceZipSha1);
      System.out.println();
    }

    File binZip = get(binZipUrl);
    String calculatedBinZipSha1 = sha1(binZip);
    String binZipSha1 = FileUtils.fileRead(get(binZipSha1Url));
    if (calculatedBinZipSha1.equals(binZipSha1)) {
      System.out.println("Calculated SHA1 of binary ZIP matches published SHA1 of binary ZIP.");
      System.out.println(binZipSha1);
      System.out.println();
    }

    // /tmp/binary
    File mavenBinaryDirectory = new File(temp, "binary");
    // /tmp/binary/apache-maven-3.1.1
    unpackZipFile(binZip, mavenBinaryDirectory);

    // /tmp/source
    File mavenSourceArchiveUnpackDirectory = new File(temp, "source");
    unpackZipFile(sourceZip, mavenSourceArchiveUnpackDirectory);
    // /tmp/source/apache-maven-3.1.1
    File mavenSourceArchiveDirectory = new File(mavenSourceArchiveUnpackDirectory, String.format("%s-%s", artifactId, version));

    ZipFile mavenCore = new ZipFile(new File(mavenBinaryDirectory, String.format("%s-%s/lib/maven-core-%s.jar", artifactId, version, version)));
    Properties p = new Properties();
    try (InputStream is = mavenCore.getInputStream(mavenCore.getEntry("org/apache/maven/messages/build.properties"))) {
      p.load(is);
    }
    mavenCore.close();

    String releaseRevision = p.getProperty("buildNumber");
    System.out.println("Git revision of release as determined from maven-core-3.1.1.jar:org/apache/maven/messages/build.properties(buildNumber):");
    System.out.println(releaseRevision);
    System.out.println();

    // Retrieve the source revision
    File gitCheckout = new File(temp, "source-checkout");
    if (gitCheckout.exists() == false) {
      GitProvider git = new GitProvider("https://git-wip-us.apache.org/repos/asf/maven.git", releaseRevision, gitCheckout);
      git.checkout();
    }

    //
    // Compare each entry in the source archive to make sure it is present in the release revision 
    //
    List<String> filesThatDoNotExistInGitRevision = new ArrayList<String>();
    List<String> filesThatDoNotHaveMatchingSha1s = new ArrayList<String>();
    List<File> sourceArchiveFiles = FileUtils.getFiles(mavenSourceArchiveDirectory, null, null);
    for (File sourceArchiveFile : sourceArchiveFiles) {
      String baseSourceFileName = sourceArchiveFile.getCanonicalPath().substring(mavenSourceArchiveDirectory.getCanonicalPath().length() + 1);
      File gitCheckoutSourceFile = new File(gitCheckout, baseSourceFileName);

      if (gitCheckoutSourceFile.exists() == false) {
        filesThatDoNotExistInGitRevision.add(baseSourceFileName);
        continue;
      }

      if (sha1sMatch(sourceArchiveFile, gitCheckoutSourceFile) == false) {
        filesThatDoNotHaveMatchingSha1s.add(baseSourceFileName);
      }
    }

    if (filesThatDoNotExistInGitRevision.isEmpty() == false) {
      System.out.println("Files that are present in the source distribution but not in the source revision:");
      for (String s : filesThatDoNotExistInGitRevision) {
        System.out.println(s);
      }
      System.out.println();
    }

    if (filesThatDoNotHaveMatchingSha1s.isEmpty() == false) {
      System.out.println("Files that do not have matching sha1s:");
      for (String s : filesThatDoNotHaveMatchingSha1s) {
        System.out.println(s);
      }
    }
  }

  private boolean sha1sMatch(File a, File b) throws IOException {
    return sha1(a).equals(sha1(b));
  }

  private boolean urlExists(String url) throws IOException {
    HttpURLConnection ohc = (HttpURLConnection) new URL(url).openConnection();
    ohc.setRequestMethod("HEAD");
    return ohc.getResponseCode() == 200;
  }

  private File get(String url) throws IOException {

    //File file = File.createTempFile("sebbalizer-", ".zip");    
    File file = new File(temp, url.substring(url.lastIndexOf('/') + 1));
    if (file.exists()) {
      return file;
    }

    if (file.getParentFile().exists() == false) {
      file.getParentFile().mkdirs();
    }

    HttpURLConnection ohc = (HttpURLConnection) new URL(url).openConnection();
    ohc.setRequestMethod("GET");
    final byte[] buffer = new byte[1024 * 1024];

    try (InputStream is = ohc.getInputStream(); OutputStream os = new BufferedOutputStream(new FileOutputStream(file));) {
      for (int count; (count = is.read(buffer)) != -1;) {
        os.write(buffer, 0, count);
      }
    }

    return file;
  }

  private void unpackZipFile(File archive, File targetDirectory) throws IOException {
    ZipFile zipFile = new ZipFile(archive);
    Enumeration<? extends ZipEntry> entries = zipFile.entries();
    while (entries.hasMoreElements()) {
      final ZipEntry zipEntry = entries.nextElement();
      if (zipEntry.isDirectory()) {
        continue;
      }
      final File targetFile = new File(targetDirectory, zipEntry.getName());
      com.google.common.io.Files.createParentDirs(targetFile);
      ByteStreams.copy(zipFile.getInputStream(zipEntry), com.google.common.io.Files.newOutputStreamSupplier(targetFile).getOutput());
    }
    zipFile.close();
  }

  public String sha1(File dataFile) throws IOException {
    MessageDigest digest = null;
    try {
      digest = MessageDigest.getInstance("SHA-1");
    } catch (NoSuchAlgorithmException e1) {
      // Not going to happen
    }

    FileInputStream fis = new FileInputStream(dataFile);
    try {
      for (byte[] buffer = new byte[32 * 1024];;) {
        int read = fis.read(buffer);
        if (read < 0) {
          break;
        }
        digest.update(buffer, 0, read);
      }
    } finally {
      try {
        fis.close();
      } catch (IOException e) {
        // ignored
      }
    }

    return toHexString(digest.digest());
  }

  public static String toHexString(byte[] bytes) {
    if (bytes == null) {
      return null;
    }

    StringBuilder buffer = new StringBuilder(bytes.length * 2);

    for (int i = 0; i < bytes.length; i++) {
      int b = bytes[i] & 0xFF;
      if (b < 0x10) {
        buffer.append('0');
      }
      buffer.append(Integer.toHexString(b));
    }

    return buffer.toString();
  }

  public static void main(String[] args) throws Exception {
    String url2 = "https://repository.apache.org/content/repositories/maven-065/";
    SourceReleaseAnalyzer s = new SourceReleaseAnalyzer("org.apache.maven", "apache-maven", "3.1.1", url2);
    s.sebbalize();
  }
}
