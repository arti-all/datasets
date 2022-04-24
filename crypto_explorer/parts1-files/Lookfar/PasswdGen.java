package com.vaguehope.lookfar.auth;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;

public class PasswdGen {

	private static final int INIT_SIZE_BYTES = 512;
	private static final long RESEED_INTERVAL_MILLIES = TimeUnit.HOURS.toMillis(1);
	private static final int SEED_SIZE_BYTES = 16; // FIXME is this a good value for this?
	private static final int PASSWD_SIZE_BITS = 130;
	private static final int PASSWD_RADIX = 32;

	private final Supplier<SecureRandom> srs = Suppliers.memoize(new SecureRandomSupplier());
	private final AtomicLong lastSeed = new AtomicLong();

	public PasswdGen () {}

	public String makePasswd () {
		SecureRandom sr = this.srs.get();
		if (System.currentTimeMillis() - this.lastSeed.get() > RESEED_INTERVAL_MILLIES) {
			sr.setSeed(SecureRandom.getSeed(SEED_SIZE_BYTES));
			this.lastSeed.set(System.currentTimeMillis());
		}
		return String.format("%-26s", new BigInteger(PASSWD_SIZE_BITS, sr).toString(PASSWD_RADIX)).replace(' ', '_');
	}

	private static class SecureRandomSupplier implements Supplier<SecureRandom> {

		private static final Logger LOG = LoggerFactory.getLogger(PasswdGen.SecureRandomSupplier.class);

		public SecureRandomSupplier () {}

		@Override
		public SecureRandom get () {
			SecureRandom sr = getSr();
			LOG.info("SecureRandom provider: {}", sr.getProvider());
			sr.nextBytes(new byte[INIT_SIZE_BYTES]);
			return sr;
		}

		private static SecureRandom getSr () {
			try {
				return SecureRandom.getInstance("SHA1PRNG");
			}
			catch (NoSuchAlgorithmException e) {
				return new SecureRandom();
			}
		}

	}

}
