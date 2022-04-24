package com.mto.rajant;

import com.mto.rajant.bcapi.BcapiAuthHandler;
import com.mto.rajant.bcapi.BcapiMessageDecoder;
import com.mto.rajant.bcapi.BcapiMessageEncoder;
import com.mto.rajant.bcapi.BcapiWireDecoder;
import com.mto.rajant.bcapi.BcapiWireEncoder;
import com.rajant.bcapi.protos.BCAPIProtos;
import com.rajant.bcapi.protos.GpsProtos;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;


/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date: 2/20/17
 */
public class Session {

    private final Callback _callback;

    private final BcapiAuthHandler _authHandler;

    private final Channel _channel;

    private final AtomicLong _seq = new AtomicLong(0);

    private final String _id = UUID.randomUUID().toString();

    private String _name = "";

    private String _role = "co";

    private String _password = "breadcumb-co";

    public Session(InetAddress addr, int port, String role, String password, Callback callback) {
        _role = role;
        _password = password;
        _callback = callback;
        _authHandler = new BcapiAuthHandler(this, callback);
        _channel = connect(addr, port).channel();
    }

    public String getId() {
        return _id;
    }

    public String getName() {
        return _name;
    }

    public void setName(String name){
        _name = name;
    }

    public String getRole(){
        return _role;
    }

    public String getPassword(){
        return _password;
    }

    public BCAPIProtos.BCMessage.Builder createMessage() {
        return BCAPIProtos.BCMessage.newBuilder().setSequenceNumber(_seq.getAndIncrement());
    }

    public void send(BCAPIProtos.BCMessage msg) {
        _channel.writeAndFlush(msg);
    }
    
    public void askGPS() {
        BCAPIProtos.BCMessage.Builder msgb = createMessage();
        msgb.setGps((GpsProtos.GPS) null);
        send(msgb.build());
    }

    public void close() {
        _channel.close();
    }

    public void awaitAuthentication() {
        _authHandler.await();
    }

    public void awaitClose() {
        _channel.closeFuture().syncUninterruptibly();
    }

    private ChannelFuture connect(InetAddress addr, int port) {
        EventLoopGroup group = new NioEventLoopGroup();
        Bootstrap b = new Bootstrap()
                .group(group)
                .channel(NioSocketChannel.class)
                .handler(new Handler());
        return b.connect(addr, port);
    }

    private class Handler extends ChannelInitializer<SocketChannel> {

        @Override
        protected void initChannel(SocketChannel c) throws Exception {
            SSLEngine ssl = createEngine();
            ssl.setUseClientMode(true);

            ChannelPipeline p = c.pipeline();

            p.addLast("ssl", new SslHandler(ssl));

            p.addLast("in-bcapi-wire", new BcapiWireDecoder());
            p.addLast("in-bcapi-message", new BcapiMessageDecoder());
            p.addLast("in-auth", _authHandler);
            p.addLast("in-callback", new CallbackHandler());

            p.addLast("out-bcapi-wire", new BcapiWireEncoder());
            p.addLast("out-bcapi-message", new BcapiMessageEncoder());
        }

        private SSLEngine createEngine() throws Exception {
            SSLContext ctx = SSLContext.getInstance("TLSv1.2");
            TrustManager[] tms = new TrustManager[]{new PermissiveTrustManager()};
            ctx.init(null, tms, new SecureRandom());
            return ctx.createSSLEngine();
        }
    }

    private class CallbackHandler extends ChannelInboundHandlerAdapter {

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            _callback.messageReceived(Session.this, (BCAPIProtos.BCMessage) msg);
        }
    }

    private static class PermissiveTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}
