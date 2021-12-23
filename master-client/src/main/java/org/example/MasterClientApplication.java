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
public class MasterClientApplication {

    private static AtomicBoolean shutdown;
    private static SocketChannel socketChannel;
    private static Selector selector;
    private static PrivateKey privateKey;

    private static int participatorCount = 0;
    private static int seqId = 0;
    private static List<PublicKey> allPubKey = new CopyOnWriteArrayList<>();
    private static List<Key> allMidKey = new CopyOnWriteArrayList<>();
    private static KeyAgreement keyAgreement;

    public static void shutdown() {
        shutdown.set(true);
    }

    private static void init() throws IOException {
        shutdown = new AtomicBoolean(false);
        selector = Selector.open();
        socketChannel = SocketChannel.open();
        socketChannel.configureBlocking(false);
    }

    public static void main(String[] argv) throws IOException {
        init();
        String host = "127.0.0.1";
        int port = 9553;
        if (connect(host, port)) {
            log.info("连接成功");
            Message.write(MessageType.CLIENT_TYPE, new byte[]{(byte) ParticipatorInfo.Type.MASTER.ordinal()}, socketChannel);
        } else {
            log.error("无法连接服务器");
            return;
        }
        socketChannel.register(selector, SelectionKey.OP_READ);
        Thread eventThread = new Thread(() -> {
            log.info("startup");
            while (!shutdown.get()) {
                try {
                    selector.select(key -> {
                        try {
                            read(key);
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

        Runtime.getRuntime().addShutdownHook(new Thread(MasterClientApplication::shutdown));

    }

    private static boolean connect(String host, int port) {
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

    private static void read(SelectionKey key) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
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

    private static void readClientId(Message message, SelectionKey key) throws IOException {
        seqId = message.getData()[0];
        Message.write(CLIENT_ID, new byte[]{(byte) seqId}, socketChannel);
    }

    private static void readParticipatorCount(Message message, SelectionKey key) {
        participatorCount = message.getData()[0];
    }


    private static void readServerPubKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, IOException {
        PublicKey serverPubKey = KeyExchange.decodePublicKey(message.getData());

        KeyPair keyPair = KeyExchange.generate(serverPubKey);
        privateKey = keyPair.getPrivate();
        Message.write(CLIENT_PUB, keyPair.getPublic().getEncoded(), socketChannel);
    }

    private static void readClientPubKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
        allPubKey.add(KeyExchange.decodePublicKey(message.getData()));
        if (allPubKey.size() == participatorCount) {
            int nextPubKeyPosition = seqId + 1;
            if (nextPubKeyPosition == allPubKey.size()) {
                nextPubKeyPosition = 0;
            }
            keyAgreement = KeyExchange.getKeyAgreement();
            Key midKey = KeyExchange.generateSecretKey(keyAgreement, privateKey, allPubKey.get(nextPubKeyPosition), false);
            Message.write(MID_KEY, midKey.getEncoded(), socketChannel);
        }
    }

    private static void readClientMidKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IOException {
        allMidKey.add(KeyExchange.decodeKey(message.getData()));
        for (int i = 1; i <= participatorCount - 2; i++) {
            int nextPubKeyPosition = seqId + i;
            if (nextPubKeyPosition == allPubKey.size()) {
                nextPubKeyPosition = 0;
            }
            keyAgreement.doPhase(allMidKey.get(nextPubKeyPosition), i == participatorCount - 2);
        }
        String secret = Hex.encodeHexString(keyAgreement.generateSecret());
        log.error("secret={}", secret);
    }

    private static void readOther(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {

    }
}
