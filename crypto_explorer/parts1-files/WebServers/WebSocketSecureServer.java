package com.webservers;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.TrustManagerFactory;
import net.iharder.Base64;

public class WebSocketSecureServer {

    private static SSLEngine sslEngine = null;
    private static SSLContext sslContext = null;
    private static final int port = 1500;
    private static Boolean connectionOpen;
    private static ByteBuffer inputBuffer = ByteBuffer.allocate(4096);
    private static ByteBuffer outputBuffer = ByteBuffer.allocate(4096);
    private static ByteBuffer networkBuffer = ByteBuffer.allocate(4096);
    private static Boolean handshakeComplete = false;
    private static Boolean initialHSComplete = false;
    private static SSLEngineResult.HandshakeStatus initialHSStatus = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
    private static final Charset ascii = Charset.forName("US-ASCII");
    private static String request;

    public static void main(String[] args) {
        try {
            Long startTime = System.currentTimeMillis();
            AsynchronousChannelGroup group = AsynchronousChannelGroup.withThreadPool(Executors.newSingleThreadExecutor());
            final AsynchronousServerSocketChannel listener = AsynchronousServerSocketChannel.open(group).bind(new InetSocketAddress(port));
            listener.accept(null, new CompletionHandler<AsynchronousSocketChannel, Void>() {
                @Override
                public void completed(AsynchronousSocketChannel asynchronousSocketChannel, Void att) {
                    try {
                        listener.accept(null, this);

                        //Configure SSL
                        char[] password = "password".toCharArray();
                        KeyStore keystore = KeyStore.getInstance("JKS");
                        keystore.load(new FileInputStream("keystore.jks"), password);
                        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
                        keyManagerFactory.init(keystore, password);
                        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
                        trustManagerFactory.init(keystore);
                        sslContext = SSLContext.getInstance("TLS");
                        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

                        //Perform Handshake
                        inputBuffer = ByteBuffer.allocate(4096);
                        outputBuffer = ByteBuffer.allocate(4096);
                        networkBuffer = ByteBuffer.allocate(4096);
                        initialHSComplete = false;
                        handshakeComplete = false;
                        initialHSStatus = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                        sslEngine = sslContext.createSSLEngine();
                        sslEngine.setUseClientMode(false);
                        outputBuffer = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
                        outputBuffer.limit(0);
                        inputBuffer = ByteBuffer.allocate(sslEngine.getSession().getPacketBufferSize());
                        while (!handshakeComplete) {
                            handshakeComplete = doHandshake(asynchronousSocketChannel);
                        }

                        //Request - Print request to console
                        read(asynchronousSocketChannel);

                        //Response - Print response to client (echo request to client)
                        write(asynchronousSocketChannel);

                        if (isHandshake(asynchronousSocketChannel)) {
                            onOpen(asynchronousSocketChannel);
                        }
                        while (connectionOpen) {
                            inputBuffer = ByteBuffer.allocate(4096);
                            asynchronousSocketChannel.read(inputBuffer).get(2000, TimeUnit.SECONDS);
                            inputBuffer.flip();
                            if (inputBuffer.hasRemaining()) {
                                if (isMessage(asynchronousSocketChannel)) {
                                    onMessage(asynchronousSocketChannel);
                                } else if (isClose(asynchronousSocketChannel)) {
                                    onClose(asynchronousSocketChannel);
                                }
                            }
                        }
                    } catch (InterruptedException | ExecutionException | TimeoutException | IOException ex) {
                        Logger.getLogger(WebSocketSecureServer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (Exception ex) {
                        Logger.getLogger(WebSocketSecureServer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                @Override
                public void failed(Throwable exc, Void att) {
                }
            });

            Long endTime = System.currentTimeMillis();
            System.out.println("WebSocket Secure Server started in " + (endTime - startTime) + "ms.");
        } catch (IOException ex) {
        }

        while (true) {
            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException ex) {
            }
        }
    }

    public static Boolean isHandshake(AsynchronousSocketChannel asynchronousSocketChannel) throws ExecutionException, InterruptedException, TimeoutException {
        inputBuffer = ByteBuffer.allocate(4096);
        asynchronousSocketChannel.read(inputBuffer).get(2000, TimeUnit.SECONDS);
        inputBuffer.flip();
        String message = Charset.defaultCharset().decode(inputBuffer).toString();
        inputBuffer.flip();
        return (connectionOpen = message.contains("Upgrade: websocket"));
    }

    public static Boolean isMessage(AsynchronousSocketChannel asynchronousSocketChannel) throws Exception {
        Boolean isMessage = false;
        if (inputBuffer.hasRemaining()) {
            inputBuffer.rewind();
            String message = decodeMaskedFrame(inputBuffer);
            //If a message is sent that is equal to "CLOSE" then the connection will close (oops)
            if (!message.equals("CLOSE")) {
                isMessage = true;
            }
        }
        return isMessage;
    }

    public static Boolean isClose(AsynchronousSocketChannel asynchronousSocketChannel) throws Exception {
        Boolean isClose = false;
        inputBuffer.flip();
        if (inputBuffer.hasRemaining()) {
            inputBuffer.rewind();
            String message = decodeMaskedFrame(inputBuffer);
            if (message.equals("CLOSE")) {
                isClose = true;
            }
        }
        return isClose;
    }

    public static void onOpen(AsynchronousSocketChannel asynchronousSocketChannel) throws InterruptedException, ExecutionException, TimeoutException, NoSuchAlgorithmException {
        String WebSocketsMagicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        Properties properties = new Properties();
        StringBuilder sb = new StringBuilder();
        while (inputBuffer.hasRemaining()) {
            sb.append((char) (inputBuffer.get() & 0xff));
        }
        String[] lines = sb.toString().split("\\n");
        for (String line : lines) {
            String[] keyVal = line.split(":");
            if (keyVal.length == 2) {
                properties.put(keyVal[0].trim(), keyVal[1].trim());
            }
        }
        String message
                = "HTTP/1.1 101 Switching Protocols\r\n"
                + "Connection: Upgrade\r\n"
                + "Sec-WebSocket-Accept: " + Base64.encodeBytes(MessageDigest.getInstance("SHA1").digest((properties.getProperty("Sec-WebSocket-Key") + WebSocketsMagicString).getBytes())) + "\r\n"
                + "Upgrade: websocket\r\n"
                + "\r\n";
        outputBuffer = ByteBuffer.allocate(message.getBytes().length);
        outputBuffer.put(message.getBytes());
        outputBuffer.flip();
        while (outputBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(outputBuffer);
        }
        outputBuffer = encodeUnmaskedFrame(1, "Connection Established");
        outputBuffer.flip();
        outputBuffer.rewind();
        while (outputBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(outputBuffer);
        }
    }

    public static void onMessage(AsynchronousSocketChannel asynchronousSocketChannel) throws Exception {
        inputBuffer.flip();
        inputBuffer.rewind();
        String message = decodeMaskedFrame(inputBuffer);
        outputBuffer = encodeUnmaskedFrame(1, message);
        outputBuffer.flip();
        outputBuffer.rewind();
        while (outputBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(outputBuffer);
        }
    }

    public static void onClose(AsynchronousSocketChannel asynchronousSocketChannel) throws IOException {
        outputBuffer = encodeUnmaskedFrame(1, "Connection Closed");
        outputBuffer.flip();
        outputBuffer.rewind();
        while (outputBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(outputBuffer);
        }
        ByteBuffer closeBuffer = encodeUnmaskedFrame(8, "");
        closeBuffer.flip();
        while (closeBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(closeBuffer);
        }
        connectionOpen = false;
        asynchronousSocketChannel.close();
    }

    public static String decodeMaskedFrame(ByteBuffer buffer) throws Exception {
        StringBuilder sb = new StringBuilder();
        List<Byte> frame = new ArrayList<>();
        while (buffer.hasRemaining()) {
            frame.add(buffer.get());
        }
        Byte code = (byte) (frame.remove(0) & 127 & 0xff);
        if (code == 1) {
            int length = (int) frame.remove(0) & 127 & 0xff;
            if (length == 126) {
                length = (int) frame.remove(0) & 0xff;
                length += (int) frame.remove(0) & 0xff;
            }
            if (length == 127) {
                length = (int) frame.remove(0) & 0xff;
                length += (int) frame.remove(0) & 0xff;
                length += (int) frame.remove(0) & 0xff;
                length += (int) frame.remove(0) & 0xff;
                length += (int) frame.remove(0) & 0xff;
                length += (int) frame.remove(0) & 0xff;
                length += (int) frame.remove(0) & 0xff;
                length += (int) frame.remove(0) & 0xff;
            }
            List<Byte> masks = frame.subList(0, 4);
            List<Byte> data = frame.subList(4, frame.size());
            for (int i = 0; i < length; i++) {
                sb.append((char) (data.get(i) ^ masks.get(i % masks.size())));
            }
        } else if (code == 8) {
            sb.append("CLOSE");
        } else {
            throw new Exception("Websocket frame code: '" + code + "' is not supported.");
        }
        return sb.toString();
    }

    public static ByteBuffer encodeUnmaskedFrame(int code, String message) {
        List<Byte> frame = new ArrayList<>();
        frame.add((byte) ((short) code | (1 << 7) & 0xff));
        frame.add((byte) message.length());
        for (int i = 0; i < message.length(); i++) {
            frame.add((byte) message.charAt(i));
        }
        ByteBuffer buffer = ByteBuffer.allocate(frame.size());
        for (byte b : frame) {
            buffer.put(b);
        }
        return buffer;
    }

    private static Boolean doHandshake(AsynchronousSocketChannel asynchronousSocketChannel) throws IOException, ExecutionException, InterruptedException, RuntimeException {
        SSLEngineResult sslEngineResult;
        if (initialHSComplete) {
            return initialHSComplete;
        }
        if (outputBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(outputBuffer);
            if (outputBuffer.hasRemaining()) {
                return false;
            }
            switch (initialHSStatus) {
                case FINISHED:
                    initialHSComplete = true;
                case NEED_UNWRAP:
                    break;
            }
            return initialHSComplete;
        }
        switch (initialHSStatus) {
            case NEED_UNWRAP:
                if (asynchronousSocketChannel.read(inputBuffer).get() == -1) {
                    sslEngine.closeInbound();
                    return initialHSComplete;
                }
                needIO:
                while (initialHSStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {
                    ByteBuffer bb2 = ByteBuffer.allocate(networkBuffer.limit());
                    inputBuffer.flip();
                    bb2.put(inputBuffer);
                    inputBuffer = bb2;
                    inputBuffer.flip();
                    sslEngineResult = sslEngine.unwrap(inputBuffer, networkBuffer);
                    inputBuffer.compact();
                    initialHSStatus = sslEngineResult.getHandshakeStatus();
                    switch (sslEngineResult.getStatus()) {
                        case OK:
                            switch (initialHSStatus) {
                                case NOT_HANDSHAKING:
                                case NEED_TASK:
                                    Runnable runnable;
                                    while ((runnable = sslEngine.getDelegatedTask()) != null) {
                                        runnable.run();
                                    }
                                    initialHSStatus = sslEngine.getHandshakeStatus();
                                    break;
                                case FINISHED:
                                    initialHSComplete = true;
                                    break needIO;
                            }
                            break;
                        case BUFFER_UNDERFLOW:
                            break needIO;
                        case BUFFER_OVERFLOW:
                            break;
                    }
                }
                if (initialHSStatus != SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                    break;
                }
            case NEED_WRAP:
                outputBuffer.clear();
                sslEngineResult = sslEngine.wrap(ByteBuffer.allocate(0), outputBuffer);
                outputBuffer.flip();
                initialHSStatus = sslEngineResult.getHandshakeStatus();
                switch (sslEngineResult.getStatus()) {
                    case OK:
                        if (initialHSStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                            Runnable runnable;
                            while ((runnable = sslEngine.getDelegatedTask()) != null) {
                                runnable.run();
                            }
                            initialHSStatus = sslEngine.getHandshakeStatus();
                        }
                        if (initialHSComplete) {
                            write(asynchronousSocketChannel);
                        }
                        break;
                }
                break;
        }
        return initialHSComplete;
    }

    private static void read(AsynchronousSocketChannel asynchronousSocketChannel) throws IOException, ExecutionException, IllegalStateException, InterruptedException, TimeoutException {
        SSLEngineResult sslEngineResult;
        if (asynchronousSocketChannel.read(inputBuffer).get() == -1) {
            sslEngine.closeInbound();
        }
        do {
            ByteBuffer byteBuffer = ByteBuffer.allocate(networkBuffer.limit());
            inputBuffer.flip();
            byteBuffer.put(inputBuffer);
            inputBuffer = byteBuffer;
            inputBuffer.flip();
            sslEngineResult = sslEngine.unwrap(inputBuffer, networkBuffer);
            asynchronousSocketChannel.read(inputBuffer).get(2000, TimeUnit.SECONDS);
            inputBuffer.flip();
            request = Charset.defaultCharset().decode(inputBuffer).toString();
            System.out.println(request + "\n\n");
            inputBuffer.compact();
            switch (sslEngineResult.getStatus()) {
                case BUFFER_OVERFLOW:
                    break;
                case BUFFER_UNDERFLOW:
                    if (sslEngine.getSession().getPacketBufferSize() > inputBuffer.capacity()) {
                        byteBuffer = ByteBuffer.allocate(networkBuffer.limit());
                        outputBuffer.flip();
                        byteBuffer.put(outputBuffer);
                        outputBuffer = byteBuffer;
                        break;
                    }
                case OK:
                    if (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        Runnable runnable;
                        while ((runnable = sslEngine.getDelegatedTask()) != null) {
                            runnable.run();
                        }
                    }
                    break;
            }
        } while ((inputBuffer.position() != 0) && sslEngineResult.getStatus() != SSLEngineResult.Status.BUFFER_UNDERFLOW);
    }

    private static void write(AsynchronousSocketChannel asynchronousSocketChannel) throws IOException {
        asynchronousSocketChannel.write(outputBuffer);
        outputBuffer.clear();
        CharBuffer charBuffer = CharBuffer.allocate(1024);
        for (;;) {
            try {
                charBuffer.put("HTTP/1.0 ").put("200 OK").put("\r\n");
                charBuffer.put("Server: niossl/0.1").put("\r\n");
                charBuffer.put("Content-type: ").put("text/html; charset=iso-8859-1").put("\r\n");
                charBuffer.put("Content-length: ").put("31").put("\r\n");
                charBuffer.put("\r\n");
                charBuffer.put(request);
                charBuffer.put("<html><head><title>HttpsServer</title></head><body><h3>HelloWorld!</h3></body></html>");
                break;
            } catch (BufferOverflowException x) {
                charBuffer = CharBuffer.allocate(charBuffer.capacity() * 2);
            }
        }
        charBuffer.flip();
        SSLEngineResult sslEngineResult = sslEngine.wrap(ascii.encode(charBuffer), outputBuffer);
        outputBuffer.flip();
        switch (sslEngineResult.getStatus()) {
            case OK:
                if (sslEngineResult.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    Runnable runnable;
                    while ((runnable = sslEngine.getDelegatedTask()) != null) {
                        runnable.run();
                    }
                }
                break;
        }
        if (outputBuffer.hasRemaining()) {
            asynchronousSocketChannel.write(outputBuffer);
        }
    }

}
