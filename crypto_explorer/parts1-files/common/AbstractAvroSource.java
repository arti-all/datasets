package org.cg.common.flume;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.Security;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.apache.avro.ipc.NettyServer;
import org.apache.avro.ipc.Responder;
import org.apache.avro.ipc.Server;
import org.apache.avro.ipc.specific.SpecificResponder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.flume.Context;
import org.apache.flume.EventDrivenSource;
import org.apache.flume.FlumeException;
import org.apache.flume.conf.Configurable;
import org.apache.flume.conf.Configurables;
import org.apache.flume.instrumentation.SourceCounter;
import org.apache.flume.source.AbstractSource;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;
import org.jboss.netty.handler.codec.compression.ZlibDecoder;
import org.jboss.netty.handler.codec.compression.ZlibEncoder;
import org.jboss.netty.handler.ssl.SslHandler;
import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;


/**
 * Flume source server support avro ipc, netty and http. Based on avro flume source
 * 
 * 
 * 
 * @author yanlinwang
 *
 */
public abstract class AbstractAvroSource  extends AbstractSource implements
		EventDrivenSource, Configurable {

	protected static final Log logger = LogFactory.getLog(AbstractAvroSource.class);
	private static final String PORT_KEY = "port";
	private static final String BIND_KEY = "bind";
	private static final String PROTOCOL_KEY = "protocol";
	private static final String COMPRESSION_TYPE = "compression-type";
	private static final String SSL_KEY = "ssl";
	private static final String KEYSTORE_KEY = "keystore";
	private static final String KEYSTORE_PASSWORD_KEY = "keystore-password";
	private static final String KEYSTORE_TYPE_KEY = "keystore-type";
	public  static final String HTTP_PROTOCOL = "http";
	private static final String HTTP_CONNECTIONS = "http.connections";
	private static final String THREADS = "threads";
	private int port;
	private String bindAddress;
	private String compressionType;
	private String keystore;
	private String keystorePassword;
	private String keystoreType;
	private boolean enableSsl = false;
	private String protocol;
	private int httpConnections = 10;
	private Server nettyServer;
	private InternalHttpServer httpServer;
	private int maxThreads;
	protected SourceCounter sourceCounter;
	private ScheduledExecutorService connectionCountUpdater;
	private Class rpcProtocol;

	public AbstractAvroSource(Class rpcProtocol) {
		super();
		this.rpcProtocol = rpcProtocol;
	}
	
	@SuppressWarnings("unchecked")	
	public void configure(Context context) {
		Configurables.ensureRequiredNonNull(context, PORT_KEY, BIND_KEY);
		port = context.getInteger(PORT_KEY);
		bindAddress = context.getString(BIND_KEY);
		protocol = context.getString(PROTOCOL_KEY, HTTP_PROTOCOL);
		compressionType = context.getString(COMPRESSION_TYPE, "none");
		httpConnections = context.getInteger(HTTP_CONNECTIONS, 10);

		try {
			maxThreads = context.getInteger(THREADS, 0);
		} catch (NumberFormatException e) {
			logger.warn("can not parse max thread configuration", e);
		}

		enableSsl = context.getBoolean(SSL_KEY, false);
		keystore = context.getString(KEYSTORE_KEY);
		keystorePassword = context.getString(KEYSTORE_PASSWORD_KEY);
		keystoreType = context.getString(KEYSTORE_TYPE_KEY, "JKS");

		if (enableSsl) {
			Preconditions.checkNotNull(keystore, KEYSTORE_KEY
					+ " must be specified when SSL is enabled");
			Preconditions.checkNotNull(keystorePassword, KEYSTORE_PASSWORD_KEY
					+ " must be specified when SSL is enabled");
			try {
				KeyStore ks = KeyStore.getInstance(keystoreType);
				ks.load(new FileInputStream(keystore),
						keystorePassword.toCharArray());
			} catch (Exception ex) {
				throw new FlumeException(
						"flow source configured with invalid keystore: "
								+ keystore, ex);
			}
		}

		if (sourceCounter == null) {
			sourceCounter = new SourceCounter(getName());
		}
		
		customConfig(context);
	}

	
	/**
	 * give the chance to its sub class to configure the source 
	 * 
	 * @param context
	 */
	abstract public void customConfig(Context context);

	
	
	/**
	 * start the flume source server
	 */
	public void start() {
		logger.info(String.format("avro source server %s starting ...", this));

		if (HTTP_PROTOCOL.equals(protocol))
			startHttp();
		else
			startNetty();
		sourceCounter.start();
		super.start();
		logger.info(String.format("avro source server %s started", this));
	}

	public void startNetty() {
		Responder responder = new SpecificResponder(rpcProtocol,
				this);

		NioServerSocketChannelFactory socketChannelFactory = initSocketChannelFactory();

		ChannelPipelineFactory pipelineFactory = initChannelPipelineFactory();

		nettyServer = new NettyServer(responder, new InetSocketAddress(
				bindAddress, port), socketChannelFactory, pipelineFactory, null);

		connectionCountUpdater = Executors.newSingleThreadScheduledExecutor();

		nettyServer.start();

		logger.info("before starting NettyServer");
		final NettyServer srv = (NettyServer) nettyServer;
		connectionCountUpdater.scheduleWithFixedDelay(new Runnable() {

			
			public void run() {
				sourceCounter.setOpenConnectionCount(Long.valueOf(srv
						.getNumActiveConnections()));
			}
		}, 0, 60, TimeUnit.SECONDS);
	}

	public void startHttp() {
		Responder responder = new SpecificResponder(rpcProtocol,
				this);

		try {
			httpServer = new InternalHttpServer(responder, port,
					httpConnections);
		} catch (IOException e) {
			logger.error("failed to start http server", e);
		}
		httpServer.start();
	}

	private NioServerSocketChannelFactory initSocketChannelFactory() {
		NioServerSocketChannelFactory socketChannelFactory;
		if (maxThreads <= 0) {
			socketChannelFactory = new NioServerSocketChannelFactory(
					Executors.newCachedThreadPool(),
					Executors.newCachedThreadPool());
		} else {
			socketChannelFactory = new NioServerSocketChannelFactory(
					Executors.newCachedThreadPool(),
					Executors.newFixedThreadPool(maxThreads));
		}
		return socketChannelFactory;
	}

	private ChannelPipelineFactory initChannelPipelineFactory() {
		ChannelPipelineFactory pipelineFactory;
		boolean enableCompression = compressionType.equalsIgnoreCase("deflate");
		if (enableCompression || enableSsl) {
			pipelineFactory = new SSLCompressionChannelPipelineFactory(
					enableCompression, enableSsl, keystore, keystorePassword,
					keystoreType);
		} else {
			pipelineFactory = new ChannelPipelineFactory() {
				
				public ChannelPipeline getPipeline() throws Exception {
					return Channels.pipeline();
				}
			};
		}
		return pipelineFactory;
	}


	public void stop() {
		logger.info(String.format("avro source server {%s} stopping: {%s}", getName(),
				this));
		if (HTTP_PROTOCOL.equals(protocol))
			httpStop();
		else
			nettyStop();

		super.stop();
		logger.info(String.format(
				"avro source server {%s} stopped. Metrics: {%s}", getName(),
				sourceCounter));
	}

	public void httpStop() {
		httpServer.close();
		try {
			httpServer.join();
		} catch (InterruptedException e) {
			logger.info("avro source server " + getName()
					+ ": Interrupted while waiting "
					+ "for Avro server to stop. Exiting. Exception follows.", e);
		}

	}

	public void nettyStop() {
		nettyServer.close();
		sourceCounter.stop();
		connectionCountUpdater.shutdown();
		while (!connectionCountUpdater.isTerminated()) {
			try {
				Thread.sleep(100);
			} catch (InterruptedException ex) {
				logger.error(
						"Interrupted while waiting for connection count executor "
								+ "to terminate", ex);
				Throwables.propagate(ex);
			}
		}
		try {
			nettyServer.join();
		} catch (InterruptedException e) {
			logger.info("avro source server " + getName()
					+ ": Interrupted while waiting "
					+ "for Avro server to stop. Exiting. Exception follows.", e);
		}
	}

	@Override
	public String toString() {
		return "avro source server " + getName() + ": { bindAddress: "
				+ bindAddress + ", port: " + port + " }";
	}



	/**
	 * Factory of SSL-enabled server worker channel pipelines Copied from Avro's
	 * org.apache.avro.ipc.TestNettyServerWithSSL test
	 */
	protected static class SSLCompressionChannelPipelineFactory implements
			ChannelPipelineFactory {

		private boolean enableCompression;
		private boolean enableSsl;
		private String keystore;
		private String keystorePassword;
		private String keystoreType;

		public SSLCompressionChannelPipelineFactory(boolean enableCompression,
				boolean enableSsl, String keystore, String keystorePassword,
				String keystoreType) {
			this.enableCompression = enableCompression;
			this.enableSsl = enableSsl;
			this.keystore = keystore;
			this.keystorePassword = keystorePassword;
			this.keystoreType = keystoreType;
		}

		private SSLContext createServerSSLContext() {
			try {
				KeyStore ks = KeyStore.getInstance(keystoreType);
				ks.load(new FileInputStream(keystore),
						keystorePassword.toCharArray());

				// Set up key manager factory to use our key store
				KeyManagerFactory kmf = KeyManagerFactory
						.getInstance(getAlgorithm());
				kmf.init(ks, keystorePassword.toCharArray());

				SSLContext serverContext = SSLContext.getInstance("TLS");
				serverContext.init(kmf.getKeyManagers(), null, null);
				return serverContext;
			} catch (Exception e) {
				throw new Error(
						"Failed to initialize the server-side SSLContext", e);
			}
		}

		private String getAlgorithm() {
			String algorithm = Security
					.getProperty("ssl.KeyManagerFactory.algorithm");
			if (algorithm == null) {
				algorithm = "SunX509";
			}
			return algorithm;
		}

		public ChannelPipeline getPipeline() throws Exception {
			ChannelPipeline pipeline = Channels.pipeline();
			if (enableCompression) {
				ZlibEncoder encoder = new ZlibEncoder(6);
				pipeline.addFirst("deflater", encoder);
				pipeline.addFirst("inflater", new ZlibDecoder());
			}
			if (enableSsl) {
				SSLEngine sslEngine = createServerSSLContext()
						.createSSLEngine();
				sslEngine.setUseClientMode(false);
				// addFirst() will make SSL handling the first stage of decoding
				// and the last stage of encoding this must be added after
				// adding compression handling above
				pipeline.addFirst("ssl", new SslHandler(sslEngine));
			}
			return pipeline;
		}
	}

	
	
}