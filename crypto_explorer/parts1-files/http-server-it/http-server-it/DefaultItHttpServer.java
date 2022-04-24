package com.truward.it.httpserver.support;

import com.truward.it.httpserver.ItHttpServer;
import com.truward.it.httpserver.ItResponseProducer;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Default implementation of the {@link ItHttpServer}.
 * Relies on dependency injection container.
 *
 * @author Alexander Shabanov
 */
public final class DefaultItHttpServer implements ItHttpServer {

  private static final int DEFAULT_SO_TIMEOUT = 200;
  private static final int DEFAULT_PORT_RANGE_START = 25000;
  private static final int DEFAULT_PORT_RANGE_SIZE = 20000;

  /**
   * Timeout to get the socket interaction result.
   */
  private static final long DEFAULT_GET_RESULT_TIMEOUT_MILLIS = 200L;

  /**
   * Timeout to accept socket connection.
   */
  private static final long SERVER_ACCEPT_TIMEOUT_MILLIS = 100L;

  /**
   * Timeout to stop server loop, should be considerably greater than {@link #SERVER_ACCEPT_TIMEOUT_MILLIS}.
   */
  private static final long SERVER_STOP_TIMEOUT_MILLIS = 1000L;

  /**
   * Single iteration timeout to wait till server loop responds with the stop confirmation.
   */
  private static final long SERVER_STOP_ITER_TIMEOUT_MILLIS = SERVER_ACCEPT_TIMEOUT_MILLIS;


  private final Logger log = LoggerFactory.getLogger(DefaultItHttpServer.class);

  private int soTimeout;
  private int port;
  private ExecutorService executorService;

  /**
   * Flag, that indicates this server has been started and some properties can no longer be changed.
   */
  private volatile boolean started = false;

  /**
   * Flag, that indicates this server should be immediately stopped.
   */
  private final AtomicBoolean stopNow = new AtomicBoolean(false);
  /**
   * Flag, that indicates the server thread have been handled changed #stopNow flag and
   * terminated listener loop.
   */
  private final AtomicBoolean stopConfirmed = new AtomicBoolean(false);

  private final CopyOnWriteArrayList<HttpRequest> receivedRequests = new CopyOnWriteArrayList<HttpRequest>();

  private volatile ServerSocket serverSocket;

  private volatile ItResponseProducer responseProducer;

  /**
   * Public constructor.
   *
   * @param executorService Service to be used for spawning new listener threads
   */
  public DefaultItHttpServer(ExecutorService executorService) {
    this(executorService, DEFAULT_SO_TIMEOUT, -1);
  }

  /**
   * Public constructor.
   *
   * @param executorService Service to be used for spawning new listener threads
   * @param soTimeout Socket connection timeout in milliseconds. See also {@link #setSoTimeout(int)}
   * @param port Server socket listening port, will be picked automatically if negative
   */
  public DefaultItHttpServer(ExecutorService executorService, int soTimeout, int port) {
    setExecutorService(executorService);
    setSoTimeout(soTimeout);
    setPort(port);
  }

  public void setExecutorService(ExecutorService executorService) {
    if (started) {
      throw new IllegalStateException();
    }
    this.executorService = executorService;
  }

  @Override
  public void setResponseProducer(ItResponseProducer producer) {
    this.responseProducer = producer;
  }

  @Override
  public int getPort() {
    return port;
  }

  public void setPort(int port) {
    if (started) {
      throw new IllegalStateException();
    }
    this.port = port;
  }

  public void setSoTimeout(int soTimeout) {
    if (started) {
      throw new IllegalStateException();
    }
    if (soTimeout <= 0) {
      throw new IllegalArgumentException("Socket timeout should be greater than zero");
    }
    this.soTimeout = soTimeout;
  }

  @PostConstruct
  public void initialize() {
    // intialize port
    if (getPort() < 0) {
      setPort(DEFAULT_PORT_RANGE_START + new SecureRandom().nextInt(DEFAULT_PORT_RANGE_SIZE));
    }

    // initialize socket
    try {
      serverSocket = new ServerSocket(getPort());
      serverSocket.setSoTimeout(soTimeout);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }

    // start server loop
    executorService.execute(new Runnable() {
      @Override
      public void run() {
        runServerLoop();
      }
    });

    // set up the flag that indicates that the server is started
    started = true;
  }

  @PreDestroy
  public void stopServerLoop() {
    stopNow.set(true);

    // catch stopped signal
    long started = System.currentTimeMillis();
    while (!stopConfirmed.get()) {
      if ((System.currentTimeMillis() - started) > SERVER_STOP_TIMEOUT_MILLIS) {
        log.warn("Server has not been stopped in the due time, exiting");
        break;
      }

      synchronized (stopConfirmed) {
        try {
          stopConfirmed.wait(SERVER_STOP_ITER_TIMEOUT_MILLIS);
        } catch (InterruptedException e) {
          log.warn("Interrupted while destroy", e);
          Thread.interrupted();
        }
      }
    }

    log.info("Stopped");
  }

  @Override
  public List<HttpRequest> getReceivedRequests() {
    return Collections.unmodifiableList(
        Arrays.asList(receivedRequests.toArray(new HttpRequest[receivedRequests.size()])));
  }

  @Override
  public void clearReceivedRequests() {
    final List<HttpRequest> copiedRequests = getReceivedRequests();

    // clear all the previous requests
    receivedRequests.clear();

    // close all the associated entities
    for (final HttpRequest request : copiedRequests) {
      if (request instanceof HttpEntityEnclosingRequest) {
        final HttpEntityEnclosingRequest enclosingRequest = (HttpEntityEnclosingRequest) request;
        try {
          EntityUtils.consume(enclosingRequest.getEntity());
        } catch (IOException e) {
          log.warn("Consume error", e);
        }
      }
    }
  }

  private void runServerLoop() {
    try {
      while (!stopNow.get()) {
        tryAcceptSocket();
      }
    } finally {
      // emit stopped signal
      stopConfirmed.set(true);
    }

    synchronized (stopConfirmed) {
      stopConfirmed.notify();
    }
  }

  private void tryAcceptSocket() {
    final Socket clientSocket;
    try {
      clientSocket = serverSocket.accept();
    } catch (SocketTimeoutException ignored) {
      log.debug("Socket timeout - skipping");
      return;
    } catch (IOException e) {
      log.warn("Server socket accept error", e);
      return;
    }

    handle(clientSocket);
  }

  private void handle(Socket clientSocket) {
    final Future<HttpRequest> receivedDataFuture = executorService.submit(new ServerConnectionHandler(
        clientSocket, responseProducer));

    // should quickly get the expected request
    try {
      final HttpRequest receivedRequest = receivedDataFuture.get(DEFAULT_GET_RESULT_TIMEOUT_MILLIS,
          TimeUnit.MILLISECONDS);
      receivedRequests.add(0, receivedRequest);
    } catch (InterruptedException e) {
      log.warn("Interrupted", e);
    } catch (ExecutionException e) {
      log.warn("Execution error", e);
    } catch (TimeoutException e) {
      log.warn("Timeout", e);
    }
  }
}
