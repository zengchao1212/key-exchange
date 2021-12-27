package org.example;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.example.MessageType.*;

/**
 * 复合message
 * 任意方交换中断
 */
@Slf4j
public class ServerApplication {

    private final AtomicBoolean shutdown;
    private final Selector selector;
    private final PrivateKey privateKey;
    private final int participatorCount = 3;
    private final AtomicInteger seq;
    private volatile boolean masterJoin = false;
    private volatile boolean walletJoin = false;
    private volatile List<PublicKey> allPubKey;
    private volatile List<Key> allMidKey;
    private final ServerSocketChannel serverSocketChannel;

    public ServerApplication() throws IOException, NoSuchAlgorithmException {
        seq = new AtomicInteger(0);
        shutdown = new AtomicBoolean(false);
        selector = Selector.open();
        allPubKey = new CopyOnWriteArrayList<>(new PublicKey[participatorCount]);
        allMidKey = new CopyOnWriteArrayList<>(new Key[participatorCount]);
        KeyPair keyPair = KeyExchange.generate();
        privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        allPubKey.set(0, publicKey);
        allMidKey.set(0, publicKey);

        serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        serverSocketChannel.bind(new InetSocketAddress(9553));
    }

    public static void main(String[] argv) throws IOException, NoSuchAlgorithmException {
        ServerApplication serverApplication = new ServerApplication();

        serverApplication.startEstablishThread();
        serverApplication.startKeyExchangeThread();
        serverApplication.startEventThread();

        Runtime.getRuntime().addShutdownHook(new Thread(serverApplication::shutdown));
    }

    public void shutdown() {
        shutdown.set(true);
    }

    private void startEstablishThread() {
        Thread establishThread = new Thread(() -> {
            try {
                Selector establishSelector = Selector.open();
                serverSocketChannel.register(establishSelector, SelectionKey.OP_ACCEPT);
                log.info("startup");
                while (!shutdown.get()) {
                    establishSelector.select(key -> {
                        try {
                            SocketChannel clientChannel = ((ServerSocketChannel) key.channel()).accept();
                            int seqId = seq.incrementAndGet();
                            if (seqId > participatorCount) {
                                clientChannel.close();
                                key.cancel();
                                return;
                            }
                            key.attach(seqId);
                            log.info(clientChannel.getRemoteAddress().toString() + " connected");
                            clientChannel.configureBlocking(false);
                            Message.write(CLIENT_ID, new byte[]{(byte) seqId}, clientChannel);
                            Message.write(PARTICIPATOR_COUNT, new byte[]{(byte) participatorCount}, clientChannel);
                            Message.write(SERVER_PUB, allPubKey.get(0).getEncoded(), clientChannel);
                            clientChannel.register(selector, SelectionKey.OP_READ);

                        } catch (IOException e) {
                            log.error(e.getMessage());
                            key.cancel();
                        }
                    }, 1000);
                }
            } catch (Exception e) {
                log.error("线程启动失败[{}]", e.getMessage());
            }

        });

        establishThread.setName("Establish-Thread");
        establishThread.start();
    }

    private void startKeyExchangeThread() {
        Thread keyExchangeThread = new Thread(() -> {
            log.info("startup");
            while (!shutdown.get()) {
                selector.keys().forEach(key -> {
                    SocketChannel client = (SocketChannel) key.channel();
                    int currentParticipatorCount;
                    try {
                        if (!masterJoin) {
                            Message.write(TEXT, "等待master加入".getBytes(StandardCharsets.UTF_8), client);
                        } else if (!walletJoin) {
                            Message.write(TEXT, "等待wallet加入".getBytes(StandardCharsets.UTF_8), client);
                        } else if ((currentParticipatorCount = Long.valueOf(allPubKey.stream().filter(Objects::nonNull).count()).intValue()) != participatorCount) {
                            String msg = String.format("已有%d位参与者加入,共需%d位参与者", currentParticipatorCount, participatorCount);
                            Message.write(TEXT, msg.getBytes(StandardCharsets.UTF_8), client);
                        } else if ((currentParticipatorCount = Long.valueOf(allMidKey.stream().filter(Objects::nonNull).count()).intValue()) != participatorCount) {
                            ParticipatorInfo keyInfo = (ParticipatorInfo) key.attachment();
                            Message.write(CLIENT_PUB, allPubKey.get(keyInfo.getClientId() - 1).getEncoded(), client);
                            String msg = String.format("已有%d份中间密钥", currentParticipatorCount);
                            Message.write(TEXT, msg.getBytes(StandardCharsets.UTF_8), client);
                        } else {
                            Key midKey = KeyExchange.generateMiddleKey(KeyExchange.getKeyAgreement(), privateKey, allPubKey.get(participatorCount - 1), false);
                            allMidKey.set(0, midKey);
                            ParticipatorInfo keyInfo = (ParticipatorInfo) key.attachment();
                            int clientId = keyInfo.getClientId(), preClientId = clientId;
                            for (int i = 0; i < participatorCount - 2; i++) {
                                preClientId--;
                                if (preClientId == -1) {
                                    preClientId = participatorCount - 1;
                                }
                                Message.write(MID_KEY, allMidKey.get(preClientId).getEncoded(), client);
                            }
                        }
                    } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
                        log.error(e.getMessage());
                        key.cancel();
                    }

                });
                if (allMidKey.stream().filter(Objects::nonNull).count() == participatorCount) {
                    break;
                } else {
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        log.debug(e.getMessage());
                    }
                }
            }
            allPubKey = null;
            allMidKey = null;
        });
        keyExchangeThread.setName("KeyExchange-Thread");
        keyExchangeThread.start();
    }

    private void startEventThread() {
        Thread eventThread = new Thread(() -> {
            log.info("startup");
            while (!shutdown.get()) {
                try {
                    selector.select(key -> {
                        try {
                            read(key);
                        } catch (Exception e) {
                            log.error(e.getMessage());
                            key.cancel();
                        }
                    }, 1000);
                } catch (IOException e) {
                    log.error(e.getMessage());
                }
            }
        });
        eventThread.setName("Event-Thread");
        eventThread.start();
    }

    private void read(SelectionKey key) throws Exception {
        Message message = Message.read((SocketChannel) key.channel());

        if (message.getMessageType() == CLIENT_TYPE) {
            readClientType(message, key);
        } else if (message.getMessageType() == CLIENT_ID) {
            readClientId(message, key);
        } else if (message.getMessageType() == CLIENT_PUB) {
            readClientPubKey(message, key);
        } else if (message.getMessageType() == MID_KEY) {
            readMidKey(message, key);
        } else if (message.getMessageType() == ENCRYPT_DATA) {
            readEncryptData(message, key);
        } else {
            readOther(message, key);
        }
    }

    private void readClientType(Message message, SelectionKey key) {
        ParticipatorInfo info = new ParticipatorInfo();
        info.setType(ParticipatorInfo.Type.values()[message.getData()[0]]);
        key.attach(info);
        if (message.getData()[0] == ParticipatorInfo.Type.MASTER.ordinal()) {
            masterJoin = true;
        } else if (message.getData()[0] == ParticipatorInfo.Type.WALLET.ordinal()) {
            walletJoin = true;
        }
    }

    private void readClientId(Message message, SelectionKey key) {
        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
        int id = message.getData()[0];
        info.setClientId(id);
    }

    private void readClientPubKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
        allPubKey.set(info.getClientId(), KeyExchange.decodePublicKey(message.getData()));
    }

    private void readMidKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
        allMidKey.set(info.getClientId(), KeyExchange.decodePublicKey(message.getData()));
    }

    private void readEncryptData(Message message, SelectionKey key) {
        byte[] data = message.getData();
        selector.keys().forEach(item -> {
            ParticipatorInfo info = (ParticipatorInfo) item.attachment();
            if (info.getType() == ParticipatorInfo.Type.WALLET) {
                try {
                    Message.write(ENCRYPT_DATA, data, (SocketChannel) item.channel());
                } catch (IOException e) {
                    log.error(e.getMessage());
                    item.cancel();
                }
            }
        });
    }

    private void readOther(Message message, SelectionKey key) {

    }

}
