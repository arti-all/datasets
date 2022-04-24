package io.github.stephenc.diffpatch;

import difflib.DiffUtils;
import difflib.Patch;
import difflib.PatchFailedException;
import org.apache.commons.io.FileUtils;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Applies unified diff patches.
 */
@Mojo(name = "apply", threadSafe = true)
public class ApplyMojo extends AbstractMojo {
    @Parameter(defaultValue = "src/main/patches")
    private File patchDirectory;

    @Component
    private MavenProject project;

    /**
     * The character encoding scheme to be applied when applying patches.
     */
    @Parameter(property = "encoding", defaultValue = "${project.build.sourceEncoding}")
    protected String encoding;
    
    @Parameter(defaultValue = "${project.build.directory}/diffpatch-maven-plugin-markers")
    private File markersDirectory;

    public void execute() throws MojoExecutionException, MojoFailureException {
        File[] patches = patchDirectory.listFiles(new FilenameFilter() {
            public boolean accept(File dir, String name) {
                return name.endsWith(".patch");
            }
        });
        if (patches == null) {
            return;
        }
        markersDirectory.mkdirs();
        for (File p : patches) {
            getLog().info(String.format("Applying patch %s", p));
            List<String> lines;
            try {
                lines = FileUtils.readLines(p, encoding);
            } catch (IOException e) {
                throw new MojoExecutionException(String.format("Could not read %s", p), e);
            }
            int linesCount = lines.size();
            List<String> diff = new ArrayList<String>(linesCount);
            String oldFile = null;
            String newFile = null;
            slurping:
            for (int i = 0; i < linesCount; i++) {
                String line = lines.get(i);
                if (line.startsWith("--- ") && (i + 1 < linesCount) && lines.get(i + 1).startsWith("+++ ")) {
                    // this is the start of a new header section, so apply any current diff from previous section.
                    apply(diff, oldFile, newFile, p.lastModified());

                    int endIndex = line.indexOf('\t', 4);
                    // now start out the next section
                    diff.clear();
                    
                    oldFile = line.substring(4, endIndex == -1 ? line.length() : endIndex);
                    diff.add(line);
                    
                    // consume the +++ line also
                    line = lines.get(++i);
                    endIndex = line.indexOf('\t', 4);
                    newFile = line.substring(4, endIndex == -1 ? line.length() : endIndex);
                    diff.add(line);
                } else if (!line.isEmpty()) {
                    switch (line.charAt(0)) {
                        case '-':
                        case '@':
                        case '+':
                        case ' ':
                            diff.add(line);
                            continue slurping;
                        default:
                            break;
                    }
                }
            }
            apply(diff, oldFile, newFile, p.lastModified());
        }
    }

    private void apply(List<String> diff, String oldFile, String newFile, long patchLastModified) throws MojoExecutionException {
        if (!diff.isEmpty() && newFile != null && oldFile != null) {
            Patch patch = DiffUtils.parseUnifiedDiff(diff);
            try {
                boolean inPlace;
                if (oldFile.equals(newFile)) {
                    getLog().info(String.format("  Patching %s", oldFile));
                    inPlace = true;
                } else {
                    getLog().info(String.format("  Patching %s to %s", oldFile, newFile));
                    inPlace = false;
                }
                String markerName;
                try {
                    final MessageDigest digest = MessageDigest.getInstance("MD5");
                    final byte[] bytes = digest.digest(newFile.getBytes("UTF-8"));
                    final char[] chars = new char[bytes.length*2];
                    for (int i = 0; i < bytes.length; i++) {
                        chars[i*2] = Character.forDigit((bytes[i] >> 4) & 0x0f, 16);
                        chars[i*2+1] = Character.forDigit(bytes[i] & 0x0f, 16);
                    }
                    markerName = new String(chars);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException("MD5 digest mandated by JLS");
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalStateException("UTF-8 encoding mandated by JLS");
                }
                final File patchedFile = new File(project.getBasedir(), newFile);
                final File sourceFile = new File(project.getBasedir(), oldFile);
                final File markerFile = new File(markersDirectory, markerName);
                if (markerFile.isFile() && markerFile.lastModified() >= Math.max(patchLastModified, patchedFile.lastModified())) {
                    getLog().info(String.format("  Skipping %s as not modified since last time", newFile));
                    return;
                }
                FileUtils.writeLines(patchedFile, encoding, patch.applyTo(FileUtils.readLines(sourceFile, encoding)));
                new FileOutputStream(markerFile).close();
            } catch (IOException e) {
                throw new MojoExecutionException("Could not apply patch to " + newFile, e);
            } catch (PatchFailedException e) {
                throw new MojoExecutionException("Could not apply patch to " + newFile, e);
            }
        }
    }
}
