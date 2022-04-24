package org.nansun.fileduplicator;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

public class FindDupFiles {

  // file read buffer size
  private static final int BUFFER_SIZE = 4096;

  private Map<String, List<String>> map2name = new HashMap<>();
  private Map<String, List<String>> map2file = new HashMap<>();

  public void findDupByName(final Path rootDir) {
    // Symbolic link will be followed to the target file
    if (!Files.isDirectory(rootDir)) {
      System.out.println("Given directory does not exist.");
      return;
    }

    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(rootDir)) {
      for (Path child : directoryStream) {
        if (Files.isDirectory(child)) {
          findDupByName(child);
        } else {
          String fileName = child.getFileName().toString();
          List<String> list = map2name.get(fileName);
          if (list == null) {
            list = new LinkedList<String>();
            map2name.put(fileName, list);
          }
          list.add(child.toAbsolutePath().toString());
        }
      }
    } catch (IOException ex) {
      throw new RuntimeException("cannot iterate " + rootDir.toAbsolutePath(), ex);
    }
  }

  /**
   * Find all duplicate file with same content
   *
   * @param rootDir
   * @param algo
   *            hash algorithm
   * @param maxBytes
   *            first maximum bytes used to calculate hash sum. This parameter is
   *            used to improve the efficiency when calculate hash sum for
   *            very large file.
   */
  public void findDupByFile(final Path rootDir, String algo, int maxBytes) {
    // Symbolic link will be followed to the target file
    if (!Files.isDirectory(rootDir)) {
      System.out.println("Given directory does not exist.");
      return;
    }

    // Get real path of rootDir
    Path realDir = null;
    try {
      realDir = rootDir.toRealPath();
    } catch (IOException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(realDir)) {
      for (Path child : directoryStream) {
        if (Files.isDirectory(child)) {
          findDupByFile(child, algo, maxBytes);
        } else {
          String hash = getHashSum(child, algo, maxBytes);
          List<String> list = map2file.get(hash);
          if (list == null) {
            list = new LinkedList<String>();
            map2file.put(hash, list);
          }
          list.add(child.toAbsolutePath().toString());
        }
      }
    } catch (IOException ex) {
      throw new RuntimeException("cannot iterate " + rootDir.toAbsolutePath(), ex);
    }

  }

  private String getHashSum(Path path, String algo, int maxBytes) {
    String ret = "";
    try (InputStream is = Files.newInputStream(path)) {
      MessageDigest md = MessageDigest.getInstance(algo);
      DigestInputStream dis = new DigestInputStream(is, md);
      // if we want checksum for first maxBytes bytes only
      if (maxBytes > 0) {
        dis.read(new byte[maxBytes]);
        // else read whole file
      } else {
        byte[] buffer = new byte[BUFFER_SIZE];
        while (dis.read(buffer) != -1) {
          // read complete file and update the hash calculation
        }
      }
      ret = DatatypeConverter.printHexBinary(md.digest());
    } catch (IOException | NoSuchAlgorithmException ex) {
      System.err.println("WARN " + ex);
    }
    return ret;
  }

  public void printResults(Map<String, List<String>> map) {
    for (List<String> list : map.values()) {
      // Only print duplicates
      if (list.size() > 1) {
        System.out.println("--");
        for (String file : list) {
          System.out.println(file);
        }
      }
    }
    System.out.println("--");
  }

  public Map<String, List<String>> getMap2name() {
    return map2name;
  }

  public void setMap2name(Map<String, List<String>> map2name) {
    this.map2name = map2name;
  }

  public Map<String, List<String>> getMap2file() {
    return map2file;
  }

  public void setMap2file(Map<String, List<String>> map2file) {
    this.map2file = map2file;
  }

  public void main(String[] args) {
    Path rootDir;
    if (args.length < 2) {
      rootDir = Paths.get("").toAbsolutePath();
    } else {
      rootDir = Paths.get(args[1]);
    }
    // Symbolic link will be followed to the target file
    if (!Files.isDirectory(rootDir)) {
      System.out.println("Given directory does not exist.");
      return;
    }

    FindDupFiles obj = new FindDupFiles();
    obj.findDupByName(rootDir);
    obj.findDupByFile(rootDir, "SHA-512", 1024);
  }

}
