package net.theunnameddude.mcclient.netty;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import net.theunnameddude.mcclient.api.ProtocolStatus;
import net.theunnameddude.mcclient.client.MinecraftClientImpl;
import net.theunnameddude.mcclient.protocol.PacketHandler;
import net.theunnameddude.mcclient.protocol.base.BasePacket;
import net.theunnameddude.mcclient.protocol.ver1_6_4.packets.Packet02Handshake;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class MinecraftPacketHandler extends ChannelInboundHandlerAdapter {
    KeyPair keys;
    PacketHandler packetHandler;
    public MinecraftClientImpl client;
    private String host;

    public MinecraftPacketHandler(MinecraftClientImpl client, String host) {
        this.client = client;
        packetHandler = client.pc.createPacketHandler( client );
        try {
            keys = KeyPairGenerator.getInstance( "RSA" ).generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        this.host = host;
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        BasePacket packet = (BasePacket)msg;
        packet.handle( packetHandler );
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        client.setProtocolStatus( ProtocolStatus.Initial );
        client.pc.handshake( client.getAuth().getUsername(), host, client.port, client );
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        cause.printStackTrace();
        try {
            client.shutdown();
        } catch ( Exception e ) {
            e.printStackTrace();
        }
        ctx.close();
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        client.getListenerHandler().onDisconnect();
        ctx.close();
    }
}
