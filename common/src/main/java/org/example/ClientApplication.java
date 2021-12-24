package org.example;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.KeyAgreement;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.example.MessageType.*;

@Slf4j
public class ClientApplication {
    protected String secretKey;
    private AtomicBoolean shutdown;
    private SocketChannel socketChannel;
    private Selector selector;
    private PrivateKey privateKey;
    private Integer participatorCount;
    private Integer seqId;
    private List<Key> allMidKey;
    private KeyAgreement keyAgreement;
    private ParticipatorInfo.Type type;

    public ClientApplication(ParticipatorInfo.Type type) throws IOException {
        shutdown = new AtomicBoolean(false);
        selector = Selector.open();
        socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(false);
        allMidKey = new CopyOnWriteArrayList<>();
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

    private void read(SelectionKey key) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        Message message = Message.read(socketChannel);
        if (message.getMessageType() == CLIENT_ID) {
            readClientId(message, key);
        } else if (message.getMessageType() == PARTICIPATOR_COUNT) {
            readParticipatorCount(message, key);
        } else if (message.getMessageType() == SERVER_PUB) {
            readServerPubKey(message, key);
        } else if (message.getMessageType() == CLIENT_PUB) {
            readClientPubKey(message, key);
        } else if (message.getMessageType() == MID_KEY) {
            readClientMidKey(message, key);
        } else {
            readOther(message, key);
        }
    }

    private void readClientId(Message message, SelectionKey key) throws IOException {
        seqId = (int) message.getData()[0];
        Message.write(CLIENT_ID, new byte[]{seqId.byteValue()}, socketChannel);
    }

    private void readParticipatorCount(Message message, SelectionKey key) {
        participatorCount = (int) message.getData()[0];
    }


    private void readServerPubKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, IOException {
        PublicKey serverPubKey = KeyExchange.decodePublicKey(message.getData());

        KeyPair keyPair = KeyExchange.generate(serverPubKey);
        privateKey = keyPair.getPrivate();
        Message.write(CLIENT_PUB, keyPair.getPublic().getEncoded(), socketChannel);
    }

    private void readClientPubKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
        keyAgreement = KeyExchange.getKeyAgreement();
        Key midKey = KeyExchange.generateSecretKey(keyAgreement, privateKey, KeyExchange.decodePublicKey(message.getData()), false);
        Message.write(MID_KEY, midKey.getEncoded(), socketChannel);
    }

    private void readClientMidKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
        allMidKey.add(KeyExchange.decodeKey(message.getData()));
        if (allMidKey.size() == participatorCount - 2) {
            for (int i = 0; i < allMidKey.size() - 1; i++) {
                keyAgreement.doPhase(allMidKey.get(i), false);
            }
            keyAgreement.doPhase(allMidKey.get(allMidKey.size() - 1), true);
            secretKey = Hex.encodeHexString(keyAgreement.generateSecret());
            afterExchange();
        }
    }

    private void readOther(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {

    }

    protected void afterExchange() {
        log.error("secret={}", secretKey);
    }
}