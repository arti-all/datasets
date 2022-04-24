package net.theunnameddude.mcclient.protocol.ver1_6_4;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.theunnameddude.mcclient.api.ProtocolStatus;
import net.theunnameddude.mcclient.client.MinecraftClientImpl;
import net.theunnameddude.mcclient.client.PlayerImpl;
import net.theunnameddude.mcclient.client.ServerInfo;
import net.theunnameddude.mcclient.encryption.EncryptionDecoder;
import net.theunnameddude.mcclient.encryption.EncryptionEncoder;
import net.theunnameddude.mcclient.encryption.EncryptionUtil;
import net.theunnameddude.mcclient.protocol.PacketHandler;
import net.theunnameddude.mcclient.protocol.base.*;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.*;

@RequiredArgsConstructor
public class PacketHandler1_6_4 extends PacketHandler {
    @NonNull
    MinecraftClientImpl client;

    public SecretKey secretKey;
    PublicKey serverPubKey;

    public void handle(PacketEncryptionResponseBase packet) {
        if ( packet.getSharedSecret().length == 0 && packet.getToken().length == 0 ) {
            try {
                Cipher decoder = Cipher.getInstance( "AES/CFB8/NoPadding" );
                decoder.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(secretKey.getEncoded()));
                client.getChannel().pipeline().addBefore("packet-decoder", "decrypter", new EncryptionDecoder(decoder));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
            client.sendPacket( client.pc.packetClientStatus() );
        }
    }

    public void handle(PacketEncryptionRequestBase packet) {
        client.setProtocolStatus( ProtocolStatus.Authenticating );
        if ( packet.getServerId().equals("-")) {
            client.sendPacket( client.pc.packetClientStatus() );
        } else {
            try {
                this.secretKey = EncryptionUtil.getSecret();
                serverPubKey = EncryptionUtil.getPubkey( packet.getPublicKey() );

                byte[] sharedKey = EncryptionUtil.encryptData(serverPubKey, secretKey.getEncoded());
                byte[] token = EncryptionUtil.encryptData(serverPubKey, packet.getToken());

                PacketEncryptionResponseBase response = client.pc.packetEncryptionResponse( sharedKey, token );

                MessageDigest sha1 = MessageDigest.getInstance( "SHA-1" );
                sha1.update(packet.getServerId().trim().getBytes("ISO_8859_1"));
                sha1.update( secretKey.getEncoded() );
                sha1.update( serverPubKey.getEncoded() );

                String serverIdStr = new BigInteger( sha1.digest() ).toString( 16 );

                StringBuilder stringurl = new StringBuilder();
                String urlStr = "http://session.minecraft.net/game/joinserver.jsp";
                stringurl.append( "http://session.minecraft.net/game/joinserver.jsp" )
                        .append( "?user=" ).append( URLEncoder.encode(client.getAuth().getUsername(), "UTF-8" ) )
                        .append( "&sessionId=" ).append( URLEncoder.encode( client.getAuth().getConnectId(), "UTF-8" ) )
                        .append( "&serverId=" ).append(URLEncoder.encode(serverIdStr, "UTF-8"));

                try {
                    URL url = new URL( stringurl.toString() );
                    BufferedReader reader = new BufferedReader( new InputStreamReader( url.openConnection().getInputStream() ) );
                    String urlResponse = reader.readLine();

                    if ( !"OK".equals(urlResponse) ) {
                        client.getListenerHandler().onAuthFail(urlResponse);
                    } else {
                        client.sendPacket( client.pc.packetEncryptionResponse( sharedKey, token ) );

                    }

                    reader.close();
                    Cipher encoder = Cipher.getInstance( "AES/CFB8/NoPadding" );
                    encoder.init( Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec( secretKey.getEncoded() ) );
                    client.getChannel().pipeline().addBefore("packet-decoder", "encrypter", new EncryptionEncoder(encoder));
                } catch (MalformedURLException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }

                //ctx.pipeline().addBefore( "packet-decoder", "decrypt", new EncryptionEncoder( cipher ) );
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
        }
    }

    public static String urlEnc( String str ) {
        try {
            return URLEncoder.encode(str, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }

    public void handle(PacketKickBase packet) {
        client.getListenerHandler().onKick( packet.getReason() );
        client.setProtocolStatus( ProtocolStatus.Disconnected );
    }

    public void handle(PacketClientStatusBase packet) {

    }

    public void handle(PacketPluginMessageBase packet) {
        client.getListenerHandler().onPluginMessage( packet );
    }

    public void handle(PacketKeepAliveBase packet) {
        client.sendPacket( packet );
    }

    public void handle(PacketLoginRequestBase packet) {
        client.player = new PlayerImpl( packet.getEntityId(), client );
        client.getListenerHandler().onServerInfo(new ServerInfo( packet.getEntityId(), packet.getDifficulty(), packet.getDimention(),
                packet.getGameMode(), packet.getLevelType(), packet.getMaxPlayers()) );
        client.getListenerHandler().onConnected();
        client.setProtocolStatus( ProtocolStatus.Done );
    }

    public void handle(PacketSpawnPositionBase packet) {

    }

    public void handle(PacketRespawnBase packet) {
        client.getListenerHandler().onRespawn( packet );
    }

    public void handle(PacketPlayerPositionBase packet) {

    }

    public void handle(PacketPositionAndLookBase packet) {
        client.player.setLocation(packet.getZ(), packet.getY(), packet.getZ(), packet.getStance(), packet.getYaw(),
                packet.getPitch(), packet.isOnGround());
    }

    public void handle(PacketTeamBase packet) {
        client.getListenerHandler().onTeamPacket( packet );
    }

    public void handle(PacketChatBase packet) {
        client.getListenerHandler().onChat( packet.getMessage() );
    }

    public void handle(PacketPlayerListItemBase packet) {
        client.pingLock.writeLock().lock();
        try {
            if ( packet.isOnline() ) {
                client.pingMap.put( packet.getName(), packet.getPing() );
            } else {
                client.pingMap.remove( packet.getName() );
            }
        } finally {
            client.pingLock.writeLock().unlock();
        }
        client.getListenerHandler().onPing();
    }
}
