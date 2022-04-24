import java.security.SecureRandom;
import jsr166.concurrent.ForkJoinPool;
import jsr166.concurrent.ForkJoinWorkerThread;
import jsr166.concurrent.atomic.AtomicInteger;

class WorkerThread extends ForkJoinWorkerThread {

  private static final AtomicInteger INDEX_COUNTER = new AtomicInteger();


  public volatile long p0, p1, p2, p3, p4, p5, p6, p7;
  public volatile long q0, q1, q2, q3, q4, q5, q6, q7;
  private final int index;
  private long rand = new SecureRandom().nextInt();
  private long requestCounter;
  private long latencyCounter;
  private long requestIdCounter;
  public volatile long r0, r1, r2, r3, r4, r5, r6, r7;
  public volatile long s0, s1, s2, s3, s4, s5, s6, s7;

  public WorkerThread(final ForkJoinPool pool) {
    super(pool);
    this.index = INDEX_COUNTER.getAndIncrement();
  }

  private static long randomLong(long x) {
    x ^= (x << 21);
    x ^= (x >>> 35);
    x ^= (x << 4);
    return x;
  }

  public long random() {
    rand = randomLong(rand);
    return rand;
  }

  public int getIndex() {
    return index;
  }

  public void incRequestCounter(final long latency) {
    requestCounter += 1;
    latencyCounter += latency;
  }

  long getTotalRequests() {
    return requestCounter;
  }

  long getTotalLatency() {
    return latencyCounter;
  }

  public long nextRequestId() {
    return requestIdCounter++;
  }
}
