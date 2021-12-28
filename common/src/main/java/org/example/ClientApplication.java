package org.example;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.example.MessageType.*;

@Slf4j
public class ClientApplication {
    protected final SocketChannel socketChannel;
    private final AtomicBoolean shutdown;
    private final Selector selector;
    private final ParticipatorInfo.Type type;
    protected volatile SecretKey secretKey;
    private final AtomicInteger exchangeTime;
    private final KeyAgreement keyAgreement;
    private volatile int clientCount;

    public ClientApplication(ParticipatorInfo.Type type) throws IOException {
        exchangeTime = new AtomicInteger(0);
        keyAgreement = KeyExchange.getKeyAgreement();
        shutdown = new AtomicBoolean(false);
        selector = Selector.open();
        socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(false);
        this.type = type;
    }

    public static void run(ClientApplication clientApplication) throws IOException {

        String host = "127.0.0.1";
        int port = 9553;
        if (clientApplication.connect(host, port)) {
            log.info("连接成功");
            Message.write(MessageType.CLIENT_TYPE, new byte[]{(byte) clientApplication.type.ordinal()}, clientApplication.socketChannel);
        } else {
            log.error("无法连接服务器");
            return;
        }
        clientApplication.socketChannel.register(clientApplication.selector, SelectionKey.OP_READ);
        Thread eventThread = new Thread(() -> {
            log.info("startup");
            while (!clientApplication.shutdown.get()) {
                try {
                    clientApplication.selector.select(key -> {
                        try {
                            clientApplication.read(key);
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }, 1000);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        eventThread.setName("Event-Thread");
        eventThread.start();

        Runtime.getRuntime().addShutdownHook(new Thread(clientApplication::shutdown));

    }

    public void shutdown() {
        shutdown.set(true);
    }

    private boolean connect(String host, int port) {
        try {
            socketChannel.connect(new InetSocketAddress(host, port));
            socketChannel.register(selector, SelectionKey.OP_CONNECT);
            AtomicBoolean connected = new AtomicBoolean(false);
            selector.select(key -> {
                try {
                    socketChannel.finishConnect();
                    connected.set(socketChannel.isConnected());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                key.interestOps(SelectionKey.OP_READ);
            }, 2000);
            return connected.get();
        } catch (IOException e) {
            log.error(e.getMessage());
            return false;
        }
    }

    private void read(SelectionKey key) throws Exception {
        Message message = Message.read(socketChannel);
        if (message.getMessageType() == CLIENT_ID) {
            readClientId(message, key);
        } else if (message.getMessageType() == PARTICIPATOR_COUNT) {
            readParticipatorCount(message, key);
        } else if (message.getMessageType() == SERVER_PUB) {
            readServerPubKey(message, key);
        } else if (message.getMessageType() == MID_KEY) {
            readClientMidKey(message, key);
        } else if (message.getMessageType() == ENCRYPT_DATA) {
            readEncryptData(message, key);
        } else {
            readOther(message, key);
        }
    }

    private void readClientId(Message message, SelectionKey key) throws IOException {
        int seqId = message.getData()[0];
        log.error("seqId={}", seqId);
        Message.write(CLIENT_ID, new byte[]{(byte) seqId}, socketChannel);
    }

    private void readParticipatorCount(Message message, SelectionKey key) {
        clientCount = message.getData()[0];
    }


    private void readServerPubKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, IOException, InvalidKeyException {
        PublicKey serverPubKey = (PublicKey) KeyExchange.decodeKey(message.getData());
        KeyPair keyPair = KeyExchange.generate(serverPubKey);
        PrivateKey privateKey = keyPair.getPrivate();
        keyAgreement.init(privateKey);
        Message.write(MID_KEY, keyPair.getPublic().getEncoded(), socketChannel);
    }

    private void readClientMidKey(Message message, SelectionKey key) throws Exception {
        Key midKey = KeyExchange.decodeKey(message.getData());
        if (exchangeTime.incrementAndGet() == clientCount - 1) {
            keyAgreement.doPhase(midKey, true);
            secretKey = KeyExchange.generateSecretKey(keyAgreement);
            afterExchange();
        } else {
            midKey = keyAgreement.doPhase(midKey, false);
            Message.write(MID_KEY, midKey.getEncoded(), socketChannel);
        }
    }

    private void readEncryptData(Message message, SelectionKey key) {
        byte[] data = message.getData();
        data = KeyExchange.decrypt(secretKey, data);
        System.out.println(new String(data, StandardCharsets.UTF_8));
    }


    private void readOther(Message message, SelectionKey key) {

    }

    protected void afterExchange() throws Exception {
//        log.error("secret={}", Hex.encodeHexString(secretKey.getEncoded()));
    }
}
