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

@Slf4j
public class ServerApplication {

    private static AtomicBoolean shutdown;
    private static Selector selector;
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    private static volatile boolean masterJoin = false;
    private static volatile boolean walletJoin = false;

    private static int participatorCount = 3;

    private static AtomicInteger seq = new AtomicInteger(0);

    private static List<PublicKey> allPubKey = new CopyOnWriteArrayList<>(new PublicKey[participatorCount]);
    private static List<Key> allMidKey = new CopyOnWriteArrayList<>(new Key[participatorCount]);

    public static void shutdown() {
        shutdown.set(true);
    }

    private static void init() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        shutdown = new AtomicBoolean(false);
        selector = Selector.open();

        KeyPair keyPair = KeyExchange.generate();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        allPubKey.set(0, publicKey);
    }

    public static void main(String[] argv) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        init();
        ServerSocketChannel serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.bind(new InetSocketAddress(9553));
        Selector establishSelector = Selector.open();
        serverChannel.register(establishSelector, SelectionKey.OP_ACCEPT);
        Thread establishThread = new Thread(() -> {
            log.info("startup");

            while (!shutdown.get()) {
                try {
                    establishSelector.select(key -> {
                        if (key.readyOps() == SelectionKey.OP_ACCEPT) {
                            try {
                                SocketChannel clientChannel = ((ServerSocketChannel) key.channel()).accept();
                                int seqId = seq.incrementAndGet();
                                if (seqId >= participatorCount) {
                                    clientChannel.close();
                                    key.cancel();
                                    return;
                                }
                                key.attach(seqId);
                                log.info(clientChannel.getRemoteAddress().toString() + " connected");
                                clientChannel.configureBlocking(false);
                                Message.write(CLIENT_ID, new byte[]{(byte) seqId}, clientChannel);
                                Message.write(PARTICIPATOR_COUNT, new byte[]{(byte) participatorCount}, clientChannel);
                                Message.write(SERVER_PUB, publicKey.getEncoded(), clientChannel);
                                clientChannel.register(selector, SelectionKey.OP_READ);

                            } catch (IOException e) {
                                log.error(e.getMessage());
                                key.cancel();
                            }
                        }
                    }, 1000);
                } catch (IOException e) {
                    log.error(e.getMessage());
                }
            }
        });

        establishThread.setName("EstablishThread");
        establishThread.start();

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

        Thread exchangeThread = new Thread(() -> {
            log.info("startup");
            while (!shutdown.get()) {
                selector.keys().forEach(key -> {
                    SocketChannel client = (SocketChannel) key.channel();
                    try {
                        if (!masterJoin) {
                            Message.write(TEXT, "等待master加入".getBytes(StandardCharsets.UTF_8), client);
                        } else if (!walletJoin) {
                            Message.write(TEXT, "等待wallet加入".getBytes(StandardCharsets.UTF_8), client);
                        } else if (allPubKey.stream().filter(Objects::nonNull).count() != participatorCount) {
                            String msg = String.format("已有%d位其他参与者加入,共需%d位其他参与者", allPubKey.size() - 3, participatorCount - 3);
                            Message.write(TEXT, msg.getBytes(StandardCharsets.UTF_8), client);
                        } else if (allMidKey.stream().filter(Objects::nonNull).count() != participatorCount) {
                            Key midKey = KeyExchange.generateSecretKey(KeyExchange.getKeyAgreement(), privateKey, allPubKey.get(1), false);
                            allMidKey.set(0, midKey);
                            for (PublicKey item : allPubKey) {
                                Message.write(CLIENT_PUB, item.getEncoded(), client);
                            }
                            String msg = String.format("已有%d份中间密钥", allMidKey.size());
                            Message.write(TEXT, msg.getBytes(StandardCharsets.UTF_8), client);
                        } else {
                            for (Key item : allMidKey) {
                                Message.write(MID_KEY, item.getEncoded(), client);
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
        });
        exchangeThread.setName("Exchange-Thread");
        exchangeThread.start();

        Runtime.getRuntime().addShutdownHook(new Thread(ServerApplication::shutdown));
    }

    private static void read(SelectionKey key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Message message = Message.read((SocketChannel) key.channel());

        if (message.getMessageType() == CLIENT_TYPE) {
            readClientType(message, key);
        } else if (message.getMessageType() == CLIENT_ID) {
            readClientId(message, key);
        } else if (message.getMessageType() == CLIENT_PUB) {
            readClientPubKey(message, key);
        } else if (message.getMessageType() == MID_KEY) {
            readMidKey(message, key);
        } else {
            readOther(message, key);
        }
    }

    private static void readClientType(Message message, SelectionKey key) {
        ParticipatorInfo info = new ParticipatorInfo();
        info.setType(ParticipatorInfo.Type.values()[message.getData()[0]]);
        key.attach(info);
        if (message.getData()[0] == ParticipatorInfo.Type.MASTER.ordinal()) {
            masterJoin = true;
        } else if (message.getData()[0] == ParticipatorInfo.Type.WALLET.ordinal()) {
            walletJoin = true;
        }
    }

    private static void readClientId(Message message, SelectionKey key) {
        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
        int id = message.getData()[0];
        info.setClientId(id);
    }

    private static void readClientPubKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
        allPubKey.set(info.getClientId(), KeyExchange.decodePublicKey(message.getData()));
    }

    private static void readMidKey(Message message, SelectionKey key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
        allMidKey.set(info.getClientId(), KeyExchange.decodePublicKey(message.getData()));
    }

    private static void readOther(Message message, SelectionKey key) {

    }

}
