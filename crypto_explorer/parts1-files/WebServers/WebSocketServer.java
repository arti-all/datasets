package com.webservers;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.CompletionHandler;
import java.nio.charset.Charset;
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
import net.iharder.Base64;

public class WebSocketServer {

    private static final int port = 1500;
    private static Boolean connectionOpen;
    private static ByteBuffer inputBuffer;
    private static ByteBuffer outputBuffer;

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
                        Logger.getLogger(WebSocketServer.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (Exception ex) {
                        Logger.getLogger(WebSocketServer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

                @Override
                public void failed(Throwable exc, Void att) {
                }
            });

            Long endTime = System.currentTimeMillis();
            System.out.println("WebSocket Server started in " + (endTime - startTime) + "ms.");
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

}
