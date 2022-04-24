/**
 *   Copyright 2014 Prasanth Jayachandran
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package benchmarks;

import com.google.common.hash.Hashing;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import de.greenrobot.common.hash.Murmur3F;
import hasher.Murmur3;

/**
 *
 */
@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.SECONDS)
@Fork(3)
@Warmup(iterations = 10, time = 500, timeUnit = TimeUnit.MILLISECONDS)
@Measurement(iterations = 10, time = 500, timeUnit = TimeUnit.MILLISECONDS)
public class Benchmark128BitHash {

  // Just to compare against cryptographic algorithm
  @Benchmark
  public void md5(Blackhole bh, BenchmarkData bd, ByteCounter bc)
      throws NoSuchAlgorithmException, DigestException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] bytes = bd.getBytes();
    bc.add(bytes.length);
    bh.consume(md.digest(bytes));
  }

  // Just to compare against cryptographic algorithm
  @Benchmark
  public void sha(Blackhole bh, BenchmarkData bd, ByteCounter bc)
      throws NoSuchAlgorithmException, DigestException {
    MessageDigest md = MessageDigest.getInstance("SHA");
    byte[] bytes = bd.getBytes();
    bc.add(bytes.length);
    bh.consume(md.digest(bytes));
  }

  @Benchmark
  public void guava_murmur3_128(Blackhole bh, BenchmarkData bd, ByteCounter bc) {
    byte[] bytes = bd.getBytes();
    bc.add(bytes.length);
    bh.consume(Hashing.murmur3_128().hashBytes(bytes).asBytes());
  }

  @Benchmark
  public void greenrobot_murmur3f_128(Blackhole bh, BenchmarkData bd, ByteCounter bc) {
    byte[] bytes = bd.getBytes();
    bc.add(bytes.length);
    Murmur3F hf = new Murmur3F();
    hf.update(bytes);
    bh.consume(hf.getValueBytesLittleEndian());
  }

  @Benchmark
  public void murmur3_128(Blackhole bh, BenchmarkData bd, ByteCounter bc) {
    byte[] bytes = bd.getBytes();
    bc.add(bytes.length);
    bh.consume(Murmur3.hash128(bytes, bytes.length, 0));
  }

  public static void main(String[] args) throws RunnerException {
    Options options = new OptionsBuilder()
        .include(Benchmark128BitHash.class.getSimpleName())
        .forks(1)
        .build();

    new Runner(options).run();
  }
}
