/**
 * 
 */
package org.cg.common.avro;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.avro.ipc.HttpTransceiver;
import org.apache.avro.ipc.NettyTransceiver;
import org.apache.avro.ipc.Transceiver;
import org.apache.avro.ipc.specific.SpecificRequestor;
import org.apache.flume.EventDeliveryException;
import org.apache.flume.FlumeException;
import org.apache.flume.api.RpcClientConfigurationConstants;
import org.apache.flume.api.RpcClientFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.socket.SocketChannel;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;
import org.jboss.netty.handler.codec.compression.ZlibDecoder;
import org.jboss.netty.handler.codec.compression.ZlibEncoder;
import org.jboss.netty.handler.ssl.SslHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author yanlinwang
 * 
 */
public class EventIpcClient<E> {

	protected int batchSize = 1000;
	protected long connectTimeout = TimeUnit.MILLISECONDS.convert(20, TimeUnit.SECONDS);
	protected long requestTimeout = TimeUnit.MILLISECONDS.convert(20, TimeUnit.SECONDS);

	protected ExecutorService callTimeoutPool;
	protected final ReentrantLock stateLock = new ReentrantLock();
	protected URL targetUrl = null;

	/**
	 * Guarded by {@code stateLock}
	 */
	protected ConnState connState;

	protected InetSocketAddress address;
	protected boolean enableSsl;
	protected boolean trustAllCerts;
	protected String truststore;
	protected String truststorePassword;
	protected String truststoreType;
	protected boolean isHttp = true;

	protected Transceiver transceiver;

	protected Class<E> exClass;
	protected E avroClient;

	protected static final Logger logger = LoggerFactory.getLogger(EventIpcClient.class);
	protected boolean enableDeflateCompression;
	protected int compressionLevel;

	/**
	 * This constructor is intended to be called from {@link RpcClientFactory}.
	 * A call to this constructor should be followed by call to configure().
	 */
	public EventIpcClient(Class<E> exClass) {
		this.exClass = exClass;
	}

	public E getAvroClient() {
		return avroClient;
	}

	/**
	 * This method should only be invoked by the build function
	 * 
	 * @throws FlumeException
	 */
	private void connect() throws FlumeException {
		connect(connectTimeout, TimeUnit.MILLISECONDS);
	}

	/**
	 * Internal only, for now
	 * 
	 * @param timeout
	 * @param tu
	 * @throws FlumeException
	 */
	private void connect(long timeout, TimeUnit tu) throws FlumeException {
		callTimeoutPool = Executors
				.newCachedThreadPool(new TransceiverThreadFactory("Flume Avro RPC Client Call Invoker"));
		NioClientSocketChannelFactory socketChannelFactory = null;

		try {
			if (targetUrl == null) {
				targetUrl = new URL("http://" + address.getHostName() + ":" + address.getPort());
			}
			if (isHttp) {
				if (targetUrl.toString().startsWith("https://") && trustAllCerts) {
					SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
					HostnameVerifier verifier = new PermissiveHostnameVerifier();
					transceiver = new HttpsTransceiver(targetUrl, factory, verifier);
				} else {
					transceiver = new HttpTransceiver(targetUrl);
				}
			} else {
				if (enableDeflateCompression || enableSsl) {
					socketChannelFactory = new SSLCompressionChannelFactory(
							Executors.newCachedThreadPool(new TransceiverThreadFactory(
									"Avro " + NettyTransceiver.class.getSimpleName() + " Boss")),
							Executors.newCachedThreadPool(new TransceiverThreadFactory(
									"Avro " + NettyTransceiver.class.getSimpleName() + " I/O Worker")),
							enableDeflateCompression, enableSsl, trustAllCerts, compressionLevel, truststore,
							truststorePassword, truststoreType);
				} else {
					socketChannelFactory = new NioClientSocketChannelFactory(
							Executors.newCachedThreadPool(new TransceiverThreadFactory(
									"Avro " + NettyTransceiver.class.getSimpleName() + " Boss")),
							Executors.newCachedThreadPool(new TransceiverThreadFactory(
									"Avro " + NettyTransceiver.class.getSimpleName() + " I/O Worker")));
				}

				transceiver = new NettyTransceiver(this.address, socketChannelFactory, tu.toMillis(timeout));
			}
			avroClient = SpecificRequestor.getClient(this.exClass, transceiver);

		} catch (Throwable t) {
			if (callTimeoutPool != null) {
				callTimeoutPool.shutdownNow();
			}
			if (socketChannelFactory != null) {
				socketChannelFactory.releaseExternalResources();
			}
			if (t instanceof IOException) {
				throw new FlumeException(this + ": RPC connection error", t);
			} else if (t instanceof FlumeException) {
				throw (FlumeException) t;
			} else if (t instanceof Error) {
				throw (Error) t;
			} else {
				throw new FlumeException(this + ": Unexpected exception", t);
			}
		}

		setState(ConnState.READY);
	}

	public void close() throws FlumeException {
		if (callTimeoutPool != null) {
			callTimeoutPool.shutdown();
			try {
				if (!callTimeoutPool.awaitTermination(requestTimeout, TimeUnit.MILLISECONDS)) {
					callTimeoutPool.shutdownNow();
					if (!callTimeoutPool.awaitTermination(requestTimeout, TimeUnit.MILLISECONDS)) {
						logger.warn(this + ": Unable to cleanly shut down call timeout " + "pool");
					}
				}
			} catch (InterruptedException ex) {
				logger.warn(this + ": Interrupted during close", ex);
				// re-cancel if current thread also interrupted
				callTimeoutPool.shutdownNow();
				// preserve interrupt status
				Thread.currentThread().interrupt();
			}

			callTimeoutPool = null;
		}
		try {
			transceiver.close();
		} catch (IOException ex) {
			throw new FlumeException(this + ": Error closing transceiver.", ex);
		} finally {
			setState(ConnState.DEAD);
		}

	}

	@Override
	public String toString() {
		return "NettyAvroRpcClient { host: " + address.getHostName() + ", port: " + address.getPort() + " }";
	}

	/**
	 * This method should always be used to change {@code connState} so we
	 * ensure that invalid state transitions do not occur and that the
	 * {@code isIdle} {@link Condition} variable gets signaled reliably. Throws
	 * {@code IllegalStateException} when called to transition from CLOSED to
	 * another state.
	 * 
	 * @param newState
	 */
	private void setState(ConnState newState) {
		stateLock.lock();
		try {
			if (connState == ConnState.DEAD && connState != newState) {
				throw new IllegalStateException("Cannot transition from CLOSED state.");
			}
			connState = newState;
		} finally {
			stateLock.unlock();
		}
	}

	/**
	 * If the connection state != READY, throws {@link EventDeliveryException}.
	 */
	public void assertReady() throws EventDeliveryException {
		stateLock.lock();
		try {
			ConnState curState = connState;
			if (curState != ConnState.READY) {
				throw new EventDeliveryException("RPC failed, client in an invalid " + "state: " + curState);
			}
		} finally {
			stateLock.unlock();
		}
	}

	/**
	 * Helper function to convert a map of String to a map of CharSequence.
	 */
	private static Map<CharSequence, CharSequence> toCharSeqMap(Map<String, String> stringMap) {
		Map<CharSequence, CharSequence> charSeqMap = new HashMap<CharSequence, CharSequence>();
		for (Map.Entry<String, String> entry : stringMap.entrySet()) {
			charSeqMap.put(entry.getKey(), entry.getValue());
		}
		return charSeqMap;
	}

	public boolean isActive() {
		stateLock.lock();
		try {
			return (connState == ConnState.READY);
		} finally {
			stateLock.unlock();
		}
	}

	private static enum ConnState {
		INIT, READY, DEAD
	}

	/**
	 * <p>
	 * Configure the actual client using the properties. <tt>properties</tt>
	 * should have at least 2 params:
	 * <p>
	 * <tt>hosts</tt> = <i>alias_for_host</i>
	 * </p>
	 * <p>
	 * <tt>alias_for_host</tt> = <i>hostname:port</i>.
	 * </p>
	 * Only the first host is added, rest are discarded.
	 * </p>
	 * <p>
	 * Optionally it can also have a
	 * <p>
	 * <tt>batch-size</tt> = <i>batchSize</i>
	 * 
	 * @param properties
	 *            The properties to instantiate the client with.
	 * @return
	 */

	public synchronized void configure(Properties properties) throws FlumeException {
		stateLock.lock();
		try {
			if (connState == ConnState.READY || connState == ConnState.DEAD) {
				throw new FlumeException("This client was already configured, " + "cannot reconfigure.");
			}
		} finally {
			stateLock.unlock();
		}

		// batch size
		String strBatchSize = properties.getProperty(RpcClientConfigurationConstants.CONFIG_BATCH_SIZE);
		logger.debug("Batch size string = " + strBatchSize);
		batchSize = RpcClientConfigurationConstants.DEFAULT_BATCH_SIZE;
		if (strBatchSize != null && !strBatchSize.isEmpty()) {
			try {
				int parsedBatch = Integer.parseInt(strBatchSize);
				if (parsedBatch < 1) {
					logger.warn("Invalid value for batchSize: {}; Using default value.", parsedBatch);
				} else {
					batchSize = parsedBatch;
				}
			} catch (NumberFormatException e) {
				logger.warn("Batchsize is not valid for RpcClient: " + strBatchSize + ". Default value assigned.", e);
			}
		}

		// host and port
		String hostNames = properties.getProperty(RpcClientConfigurationConstants.CONFIG_HOSTS);
		String[] hosts = null;
		if (hostNames != null && !hostNames.isEmpty()) {
			hosts = hostNames.split("\\s+");
		} else {
			throw new FlumeException("Hosts list is invalid: " + hostNames);
		}

		if (hosts.length > 1) {
			logger.warn("More than one hosts are specified for the default client. "
					+ "Only the first host will be used and others ignored. Specified: " + hostNames + "; to be used: "
					+ hosts[0]);
		}

		String host = properties.getProperty(RpcClientConfigurationConstants.CONFIG_HOSTS_PREFIX + hosts[0]);
		if (host == null || host.isEmpty()) {
			throw new FlumeException("Host not found: " + hosts[0]);
		}
		String[] hostAndPort = host.split(":");
		if (hostAndPort.length != 2) {
			throw new FlumeException("Invalid hostname: " + hosts[0]);
		}
		Integer port = null;
		try {
			port = Integer.parseInt(hostAndPort[1]);
		} catch (NumberFormatException e) {
			throw new FlumeException("Invalid Port: " + hostAndPort[1], e);
		}
		this.address = new InetSocketAddress(hostAndPort[0], port);

		// connect timeout
		connectTimeout = RpcClientConfigurationConstants.DEFAULT_CONNECT_TIMEOUT_MILLIS;
		String strConnTimeout = properties.getProperty(RpcClientConfigurationConstants.CONFIG_CONNECT_TIMEOUT);
		if (strConnTimeout != null && strConnTimeout.trim().length() > 0) {
			try {
				connectTimeout = Long.parseLong(strConnTimeout);
				if (connectTimeout < 1000) {
					logger.warn("Connection timeout specified less than 1s. " + "Using default value instead.");
					connectTimeout = RpcClientConfigurationConstants.DEFAULT_CONNECT_TIMEOUT_MILLIS;
				}
			} catch (NumberFormatException ex) {
				logger.error("Invalid connect timeout specified: " + strConnTimeout);
			}
		}

		// request timeout
		requestTimeout = RpcClientConfigurationConstants.DEFAULT_REQUEST_TIMEOUT_MILLIS;
		String strReqTimeout = properties.getProperty(RpcClientConfigurationConstants.CONFIG_REQUEST_TIMEOUT);
		if (strReqTimeout != null && strReqTimeout.trim().length() > 0) {
			try {
				requestTimeout = Long.parseLong(strReqTimeout);
				if (requestTimeout < 1000) {
					logger.warn("Request timeout specified less than 1s. " + "Using default value instead.");
					requestTimeout = RpcClientConfigurationConstants.DEFAULT_REQUEST_TIMEOUT_MILLIS;
				}
			} catch (NumberFormatException ex) {
				logger.error("Invalid request timeout specified: " + strReqTimeout);
			}
		}

		String enableCompressionStr = properties.getProperty(RpcClientConfigurationConstants.CONFIG_COMPRESSION_TYPE);
		if (enableCompressionStr != null && enableCompressionStr.equalsIgnoreCase("deflate")) {
			this.enableDeflateCompression = true;
			String compressionLvlStr = properties.getProperty(RpcClientConfigurationConstants.CONFIG_COMPRESSION_LEVEL);
			compressionLevel = RpcClientConfigurationConstants.DEFAULT_COMPRESSION_LEVEL;
			if (compressionLvlStr != null) {
				try {
					compressionLevel = Integer.parseInt(compressionLvlStr);
				} catch (NumberFormatException ex) {
					logger.error("Invalid compression level: " + compressionLvlStr);
				}
			}
		}

		enableSsl = Boolean.parseBoolean(properties.getProperty(RpcClientConfigurationConstants.CONFIG_SSL));
		trustAllCerts = Boolean
				.parseBoolean(properties.getProperty(RpcClientConfigurationConstants.CONFIG_TRUST_ALL_CERTS));
		truststore = properties.getProperty(RpcClientConfigurationConstants.CONFIG_TRUSTSTORE);
		truststorePassword = properties.getProperty(RpcClientConfigurationConstants.CONFIG_TRUSTSTORE_PASSWORD);
		truststoreType = properties.getProperty(RpcClientConfigurationConstants.CONFIG_TRUSTSTORE_TYPE, "JKS");

		this.connect();
	}

	/**
	 * A thread factor implementation modeled after the implementation of
	 * NettyTransceiver.NettyTransceiverThreadFactory class which is a private
	 * static class. The only difference between that and this implementation is
	 * that this implementation marks all the threads daemon which allows the
	 * termination of the VM when the non-daemon threads are done.
	 */
	private static class TransceiverThreadFactory implements ThreadFactory {
		private final AtomicInteger threadId = new AtomicInteger(0);
		private final String prefix;

		/**
		 * Creates a TransceiverThreadFactory that creates threads with the
		 * specified name.
		 * 
		 * @param prefix
		 *            the name prefix to use for all threads created by this
		 *            ThreadFactory. A unique ID will be appended to this prefix
		 *            to form the final thread name.
		 */
		public TransceiverThreadFactory(String prefix) {
			this.prefix = prefix;
		}

		public Thread newThread(Runnable r) {
			Thread thread = new Thread(r);
			thread.setDaemon(true);
			thread.setName(prefix + " " + threadId.incrementAndGet());
			return thread;
		}
	}

	/**
	 * Factory of SSL-enabled client channels Copied from Avro's
	 * org.apache.avro.ipc.TestNettyServerWithSSL test
	 */
	private static class SSLCompressionChannelFactory extends NioClientSocketChannelFactory {

		private boolean enableCompression;
		private int compressionLevel;
		private boolean enableSsl;
		private boolean trustAllCerts;
		private String truststore;
		private String truststorePassword;
		private String truststoreType;

		public SSLCompressionChannelFactory(Executor bossExecutor, Executor workerExecutor, boolean enableCompression,
				boolean enableSsl, boolean trustAllCerts, int compressionLevel, String truststore,
				String truststorePassword, String truststoreType) {
			super(bossExecutor, workerExecutor);
			this.enableCompression = enableCompression;
			this.enableSsl = enableSsl;
			this.compressionLevel = compressionLevel;
			this.trustAllCerts = trustAllCerts;
			this.truststore = truststore;
			this.truststorePassword = truststorePassword;
			this.truststoreType = truststoreType;
		}

		@Override
		public SocketChannel newChannel(ChannelPipeline pipeline) {
			TrustManager[] managers;
			try {
				if (enableCompression) {
					ZlibEncoder encoder = new ZlibEncoder(compressionLevel);
					pipeline.addFirst("deflater", encoder);
					pipeline.addFirst("inflater", new ZlibDecoder());
				}
				if (enableSsl) {
					if (trustAllCerts) {
						logger.warn("No truststore configured, setting TrustManager to accept"
								+ " all server certificates");
						managers = new TrustManager[] { new PermissiveTrustManager() };

					} else {
						KeyStore keystore = null;

						if (truststore != null) {
							if (truststorePassword == null) {
								throw new NullPointerException("truststore password is null");
							}
							InputStream truststoreStream = new FileInputStream(truststore);
							keystore = KeyStore.getInstance(truststoreType);
							keystore.load(truststoreStream, truststorePassword.toCharArray());
						}

						TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
						// null keystore is OK, with SunX509 it defaults to
						// system CA Certs
						// see
						// http://docs.oracle.com/javase/6/docs/technotes/guides/security/jsse/JSSERefGuide.html#X509TrustManager
						tmf.init(keystore);
						managers = tmf.getTrustManagers();
					}

					SSLContext sslContext = SSLContext.getInstance("TLS");
					sslContext.init(null, managers, null);
					SSLEngine sslEngine = sslContext.createSSLEngine();
					sslEngine.setUseClientMode(true);
					// addFirst() will make SSL handling the first stage of
					// decoding
					// and the last stage of encoding this must be added after
					// adding compression handling above
					pipeline.addFirst("ssl", new SslHandler(sslEngine));
				}

				return super.newChannel(pipeline);
			} catch (Exception ex) {
				logger.error("Cannot create SSL channel", ex);
				throw new RuntimeException("Cannot create SSL channel", ex);
			}
		}
	}

	/**
	 * Permissive trust manager accepting any certificate
	 */
	private static class PermissiveTrustManager implements X509TrustManager {

		public void checkClientTrusted(X509Certificate[] certs, String s) {
			// nothing
		}

		public void checkServerTrusted(X509Certificate[] certs, String s) {
			// nothing
		}

		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
	}

	/**
	 * Permissive HostnameVerifier trust any host
	 */
	private static class PermissiveHostnameVerifier implements HostnameVerifier {

		public boolean verify(String hostname, SSLSession session) {
			// TODO Auto-generated method stub
			return true;
		}

	}
}
