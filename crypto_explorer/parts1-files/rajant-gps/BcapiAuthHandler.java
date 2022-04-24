package com.mto.rajant.bcapi;

import com.google.protobuf.ByteString;
import com.mto.rajant.Callback;
import com.mto.rajant.Compression;
import com.mto.rajant.Session;
import com.rajant.bcapi.protos.BCAPIProtos;
import com.rajant.bcapi.protos.CommonProtos;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author <a href="hoang281283@gmail.com">Minh Hoang TO</a>
 * @date: 2/20/17
 */
public class BcapiAuthHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(BcapiAuthHandler.class);

    private static final Map<String, CommonProtos.Role> ROLES = new HashMap<>();

    static {
        ROLES.put("co", CommonProtos.Role.CO);
        ROLES.put("view", CommonProtos.Role.VIEW);
        ROLES.put("local", CommonProtos.Role.LOCAL);
        ROLES.put("admin", CommonProtos.Role.ADMIN);
    }

    private static final Compression DEFAULT_COMPRESSION = Compression.GZIP;

    private final Session _session;

    private final Callback _callback;

    private final AtomicBoolean _authenticated = new AtomicBoolean(false);

    public BcapiAuthHandler(Session session, Callback callback) {
        _session = session;
        _callback = callback;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object in) throws Exception {
        BCAPIProtos.BCMessage msg = (BCAPIProtos.BCMessage) in;
        if (msg.hasAuthResult()) {
            if (msg.getAuthResult().getStatus() == BCAPIProtos.BCMessage.Result.Status.FAILURE) {
                log.error("authentication failed: " + msg.getAuthResult().getDescription());
                _session.close();
            } else {
                fireAuthenticated();
                ctx.fireChannelRead(in);
            }
        } else if (msg.hasAuth()) {
            BCAPIProtos.BCMessage.Builder response = _session.createMessage();
            response.getAuthBuilder().setAction(BCAPIProtos.BCMessage.Auth.Action.LOGIN);
            response.getAuthBuilder().setAppInstanceID(_session.getId());
            response.getAuthBuilder().setCompressionMask(DEFAULT_COMPRESSION.encode());
            response.getAuthBuilder().setRole(ROLES.get(_session.getRole()));
            response.getAuthBuilder().setChallengeOrResponse(authenticate(msg.getAuth().getChallengeOrResponse()));
            _callback.massageAuthResponse(response);
            _session.send(response.build());
        } else {
            ctx.fireChannelRead(in);
        }
    }

    public void await() {
        synchronized (_authenticated) {
            while (!_authenticated.get()) {
                try {
                    _authenticated.wait();
                } catch (InterruptedException e) {
                }
            }
        }
    }

    private void fireAuthenticated() {
        synchronized (_authenticated) {
            _authenticated.set(true);
            _authenticated.notifyAll();
        }
    }

    // to respond to an auth challenge, we use:
    //   SHA384(<password-uft8-bytes> ++ <challenge-bytes>)
    private ByteString authenticate(ByteString challenge) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-384");
        md.update(_session.getPassword().getBytes("UTF-8"));
        md.update(challenge.toByteArray());
        return ByteString.copyFrom(md.digest());
    }
}
