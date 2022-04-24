package eu.sqooss.service.cache;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.channels.FileLock;
import java.nio.channels.FileLockInterruptionException;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.OverlappingFileLockException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import eu.sqooss.service.logging.Logger;

/**
 * Disk based implementation of the cache service. Does not manage any resource
 * and puts all cached in a single directory. On a busy system, it may easily
 * hit system limits (e.g. files per directory).
 * 
 * Accepts the following system property:
 *  
 *  <dl>
 *      <dt>
 *          eu.sqooss.service.cache.dir
 *      </dt>
 *      <dd>
 *          The directory to store cache files to 
 *      </dd>
 * </dl>
 * 
 */
public class OnDiskCache extends CacheServiceImpl {

    public static final String CACHE_DIR = "eu.sqooss.service.cache.dir";
    
    private File dir;
    
    private Logger log;
    
    public OnDiskCache(String cachedir) throws Exception {
        initDir(cachedir);
    }
    
    public OnDiskCache() throws Exception {
        
        String dirpath = System.getProperty(CACHE_DIR);
        
        if (dirpath == null) {
            dirpath = System.getProperty("java.io.tmpdir");
            if (dirpath == null)
                dirpath = "tmp";
        }
        initDir(dirpath);
       
    }
    
    private void initDir(String path) throws Exception {
        dir = new File(path);

        if (!dir.exists())
            dir.mkdirs();
    }
    
    @Override
    public byte[] get(String key) {
        FileChannel file = null;
        MappedByteBuffer buff;
        FileLock lock = null;
        byte[] result = null;
        try {
            String fname = dir.getAbsolutePath() + File.separatorChar + md5(key);
            file = new FileInputStream(fname).getChannel();
            try {
                lock = file.lock(0, Long.MAX_VALUE, true);
            } catch (ClosedChannelException cce) {
                warn("Cannot store key " + key + "Cannot write to file "
                        + fname + " Channel was closed");
                return null;
            } catch (FileLockInterruptionException ace) {
                // ignored
            } catch (OverlappingFileLockException ofle) {
                // ignored
            } catch (NonWritableChannelException ofle) {
                warn("Cannot store key " + key + " File " + fname
                        + " was not opened for writing");
                return null;
            } catch (IOException ioe) {
                warn("Cannot store key " + key + " An exception occured: "
                        + ioe.getMessage());
                file.close();
                return null;
            }
            buff = file.map(MapMode.READ_ONLY, 0, file.size());
            result = new byte[(int)file.size()]; // 4GB should be enough for everybody :-)
            buff.get(result);
        } catch (Exception e) {
            return null;
        } finally {
            try {
                if (lock != null)
                    lock.release();
                if (file != null)
                    file.close();
            } catch (IOException e) {
                return null;
            }
        }

        return result;
    }
        
    @Override
    public void set(String key, byte[] data) {
        FileChannel file = null;
        MappedByteBuffer buff;
        FileLock lock = null;
        RandomAccessFile raf;

        try {
            String fname = dir.getAbsolutePath() + File.separatorChar + md5(key);
            raf = new RandomAccessFile(fname, "rw");
            file = raf.getChannel();
            try {
                lock = file.lock(0, data.length, false);
            } catch (ClosedChannelException cce) {
                warn("Cannot store key " + key + "Cannot write to file "
                        + fname + " Channel was closed");
                return;
            } catch (FileLockInterruptionException ace) {
                // ignored
            } catch (OverlappingFileLockException ofle) {
                // ignored
            } catch (NonWritableChannelException ofle) {
                warn("Cannot store key " + key + " File " + fname
                        + " was not opened for writing");
                return;
            } catch (IOException ioe) {
                warn("Cannot store key " + key + " An exception occured: "
                        + ioe.getMessage());
                file.close();
                return;
            }
            buff = file.map(MapMode.READ_WRITE, 0, data.length);
            buff.put(data);
        } catch (FileNotFoundException e) {
            warn("Cannot store key " + key + 
                    " An exception occured: "+ e.getMessage());
        } catch (Exception e) {
            warn("Cannot store key " + key + 
                    " An exception occured: "+ e.getMessage());
        }  finally {
            try {
                if (lock != null)
                    lock.release();
                if (file != null)
                    file.close();
            } catch (IOException e) {
                
            }
        }
    }

    private String md5(String...args) throws NoSuchAlgorithmException {
        MessageDigest m = MessageDigest.getInstance("MD5");
        
        for (String arg : args)
            m.update(arg.getBytes(), 0, arg.length());
        return new BigInteger(1, m.digest()).toString(16);
    }
    
    private void warn(String message) {
        if (log != null)
            log.warn(message);
        else 
            System.err.println(message);
    }
}
