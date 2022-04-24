/*
 * Copyright (c) 2012-2015, Andrea Funto'. All rights reserved. See LICENSE for details.
 */ 
package org.dihedron.core.streams;

import java.security.SecureRandom;

import org.dihedron.core.License;

/**
 * An input stream returning a random sequence of non-negative integer values; 
 * randomness is delegated to security providers and is guaranteed to have more
 * enthropy than simple #{@link java.util.Random}-based streams.
 * 
 * @author Andrea Funto'
 */
@License
public class SecureRandomInputStream extends RandomInputStream {
	
	/**
	 * Default constructor.
	 */
	public SecureRandomInputStream() {
		this(NO_LIMIT);
	}
	
	/**
	 * Constructor.
	 * 
	 * @param limit
	 *   the upper limit to the value of the random values.
	 */
	public SecureRandomInputStream(int limit) {
		super(new SecureRandom(), limit);
	}	
}
