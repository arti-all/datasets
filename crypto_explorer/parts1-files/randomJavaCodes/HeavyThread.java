package profiling;

/**
 * Created by srajendran on 7/13/15.
 */
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class HeavyThread implements Runnable {

    private long length;

    public HeavyThread(long length) {
        this.length = length;
        new Thread(this).start();
    }

    @Override
    public void run() {
        long l = 0;
        while (true) {
            l++;
//            System.out.println("INSIDE HEAVY : "+ l );
            if(l == 50){
                Thread.dumpStack();
                break;
            }
            String data = "";

            // make some shit up
            for (int i = 0; i < length; i++) {
                data += UUID.randomUUID().toString();
            }

            MessageDigest digest;
            try {
                digest = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }

            // hash that shit
            digest.update(data.getBytes());
        }
    }
}
