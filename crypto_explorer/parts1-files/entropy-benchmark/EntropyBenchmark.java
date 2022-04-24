package org.sample;

import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.openjdk.jmh.annotations.GenerateMicroBenchmark;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;

@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
public abstract class EntropyBenchmark {

    private static class XorShift32 {
        // XorShift128 PRNG with a 2^32-1 period.
        int x = System.identityHashCode(this);

        public final int nextInt() {
            x ^= (x << 6);
            x ^= (x >>> 21);
            return x ^ (x << 7);
        }
    }

    private static class XorShift128 {
        // XorShift128 PRNG with a 2^128-1 period.
        int x = System.identityHashCode(this);
        int y = -938745813;
        int z = 452465366;
        int w = 1343246171;

        public final int nextInt() {
            int t = x^(x<<15);
            //noinspection SuspiciousNameCombination
            x = y; y = z; z = w;
            return w = (w^(w>>>21))^(t^(t>>>4));
        }
    }

    public abstract int nextInt();

    //* -- Switch: Remove a leading / to observe bad JIT over-optimisation effects!

    @GenerateMicroBenchmark
    public int single() {
        return nextInt() + 1; // The +1 makes it comparable to the batching benchmark.
    }

    /*/

    @GenerateMicroBenchmark
    public int single_unadjusted() {
        return nextInt();
    }

    /*/

    // The batching benchmarks show the generators potential for benifitting
    // from instruction-level parallelism.

    @OperationsPerInvocation(20)
    @GenerateMicroBenchmark
    public int batch() {
        return nextInt() +  // 01
               nextInt() +  // 02
               nextInt() +  // 03
               nextInt() +  // 04
               nextInt() +  // 05
               nextInt() +  // 06
               nextInt() +  // 07
               nextInt() +  // 08
               nextInt() +  // 09
               nextInt() +  // 10
               nextInt() +  // 11
               nextInt() +  // 12
               nextInt() +  // 13
               nextInt() +  // 14
               nextInt() +  // 15
               nextInt() +  // 16
               nextInt() +  // 17
               nextInt() +  // 18
               nextInt() +  // 19
               nextInt();   // 20
    }

    /*/

    @OperationsPerInvocation(20)
    @GenerateMicroBenchmark
    public int batch_wrong() {
               nextInt();   // 01
               nextInt();   // 02
               nextInt();   // 03
               nextInt();   // 04
               nextInt();   // 05
               nextInt();   // 06
               nextInt();   // 07
               nextInt();   // 08
               nextInt();   // 09
               nextInt();   // 10
               nextInt();   // 11
               nextInt();   // 12
               nextInt();   // 13
               nextInt();   // 14
               nextInt();   // 15
               nextInt();   // 16
               nextInt();   // 17
               nextInt();   // 18
               nextInt();   // 19
        return nextInt();   // 20
    }
    //*/

    public static class CounterBenchmark extends EntropyBenchmark {
        private final AtomicInteger counter = new AtomicInteger();

        @Override
        public int nextInt() {
            return counter.incrementAndGet();
        }
    }

    public static class XorShift32Benchmark extends EntropyBenchmark {
        private final XorShift32 rng = new XorShift32();

        @Override
        public int nextInt() {
            return rng.nextInt();
        }
    }

    public static class XorShift128Benchmark extends EntropyBenchmark {
        private final XorShift128 rng = new XorShift128();

        @Override
        public int nextInt() {
            return rng.nextInt();
        }
    }

    public static class JavaUtilRandomBenchmark extends EntropyBenchmark {
        private final Random rng = new Random();

        @Override
        public int nextInt() {
            return rng.nextInt();
        }
    }

    public static class JavaUtilRandomUnbiasedBenchmark extends EntropyBenchmark {
        private final Random rng = new Random();
        {
            System.identityHashCode(rng);
        }

        @Override
        public int nextInt() {
            return rng.nextInt();
        }
    }

    public static class ThreadLocalRandomBenchmark extends EntropyBenchmark {
        private final ThreadLocalRandom rng = ThreadLocalRandom.current();

        @Override
        public int nextInt() {
            return rng.nextInt();
        }
    }

    public static class SecureRandomBenchmark extends EntropyBenchmark {
        private final SecureRandom rng = new SecureRandom();

        @Override
        public int nextInt() {
            return rng.nextInt();
        }
    }
}
