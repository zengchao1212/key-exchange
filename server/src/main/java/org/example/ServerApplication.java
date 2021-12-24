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

    private final AtomicBoolean shutdown;
    private final Selector selector;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final int participatorCount = 3;
    private final AtomicInteger seq;
    private volatile boolean masterJoin = false;
    private volatile boolean walletJoin = false;
    private volatile List<PublicKey> allPubKey;
    private volatile List<Key> allMidKey;

    public ServerApplication() throws IOException, NoSuchAlgorithmException {
        seq = new AtomicInteger(0);
        shutdown = new AtomicBoolean(false);
        selector = Selector.open();
        allPubKey = new CopyOnWriteArrayList<>(new PublicKey[participatorCount]);
        allMidKey = new CopyOnWriteArrayList<>(new Key[participatorCount]);
        KeyPair keyPair = KeyExchange.generate();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        allPubKey.set(0, publicKey);
        allMidKey.set(0, publicKey);
    }

    public static void main(String[] argv) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        ServerApplication serverApplication = new ServerApplication();
        ServerSocketChannel serverChannel = ServerSocketChannel.open();
        serverChannel.configureBlocking(false);
        serverChannel.bind(new InetSocketAddress(9553));
        Selector establishSelector = Selector.open();
        serverChannel.register(establishSelector, SelectionKey.OP_ACCEPT);
        Thread establishThread = new Thread(() -> {
            log.info("startup");

            while (!serverApplication.shutdown.get()) {
                try {
                    establishSelector.select(key -> {
                        if (key.readyOps() == SelectionKey.OP_ACCEPT) {
                            try {
                                SocketChannel clientChannel = ((ServerSocketChannel) key.channel()).accept();
                                int seqId = serverApplication.seq.incrementAndGet();
                                if (seqId > serverApplication.participatorCount) {
                                    clientChannel.close();
                                    key.cancel();
                                    return;
                                }
                                key.attach(seqId);
                                log.info(clientChannel.getRemoteAddress().toString() + " connected");
                                clientChannel.configureBlocking(false);
                                Message.write(CLIENT_ID, new byte[]{(byte) seqId}, clientChannel);
                                Message.write(PARTICIPATOR_COUNT, new byte[]{(byte) serverApplication.participatorCount}, clientChannel);
                                Message.write(SERVER_PUB, serverApplication.allPubKey.get(0).getEncoded(), clientChannel);
                                clientChannel.register(serverApplication.selector, SelectionKey.OP_READ);

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
            while (!serverApplication.shutdown.get()) {
                try {
                    serverApplication.selector.select(key -> {
                        try {
                            serverApplication.read(key);
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
            while (!serverApplication.shutdown.get()) {
                serverApplication.selector.keys().forEach(key -> {
                    SocketChannel client = (SocketChannel) key.channel();
                    int currentParticipatorCount;
                    try {
                        if (!serverApplication.masterJoin) {
                            Message.write(TEXT, "等待master加入".getBytes(StandardCharsets.UTF_8), client);
                        } else if (!serverApplication.walletJoin) {
                            Message.write(TEXT, "等待wallet加入".getBytes(StandardCharsets.UTF_8), client);
                        } else if ((currentParticipatorCount = Long.valueOf(serverApplication.allPubKey.stream().filter(Objects::nonNull).count()).intValue()) != serverApplication.participatorCount) {
                            String msg = String.format("已有%d位参与者加入,共需%d位参与者", currentParticipatorCount, serverApplication.participatorCount);
                            Message.write(TEXT, msg.getBytes(StandardCharsets.UTF_8), client);
                        } else if ((currentParticipatorCount = Long.valueOf(serverApplication.allMidKey.stream().filter(Objects::nonNull).count()).intValue()) != serverApplication.participatorCount) {
                            ParticipatorInfo keyInfo = (ParticipatorInfo) key.attachment();
                            Message.write(CLIENT_PUB, serverApplication.allPubKey.get(keyInfo.getClientId() - 1).getEncoded(), client);
                            String msg = String.format("已有%d份中间密钥", currentParticipatorCount);
                            Message.write(TEXT, msg.getBytes(StandardCharsets.UTF_8), client);
                        } else {
                            Key midKey = KeyExchange.generateSecretKey(KeyExchange.getKeyAgreement(), serverApplication.privateKey, serverApplication.allPubKey.get(serverApplication.participatorCount - 1), false);
                            serverApplication.allMidKey.set(0, midKey);
                            ParticipatorInfo keyInfo = (ParticipatorInfo) key.attachment();
                            int clientId = keyInfo.getClientId(), preClientId = clientId;
                            for (int i = 0; i < serverApplication.participatorCount - 2; i++) {
                                preClientId--;
                                if (preClientId == -1) {
                                    preClientId = serverApplication.participatorCount - 1;
                                }
                                Message.write(MID_KEY, serverApplication.allMidKey.get(preClientId).getEncoded(), client);
                            }
                        }
                    } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
                        log.error(e.getMessage());
                        key.cancel();
                    }

                });
                if (serverApplication.allMidKey.stream().filter(Objects::nonNull).count() == serverApplication.participatorCount) {
                    break;
                } else {
                    try {
                        Thread.sleep(5000);
                    } catch (InterruptedException e) {
                        log.debug(e.getMessage());
                    }
                }
            }
            serverApplication.allPubKey = null;
            serverApplication.allMidKey = null;
        });
        exchangeThread.setName("Exchange-Thread");
        exchangeThread.start();

        Runtime.getRuntime().addShutdownHook(new Thread(serverApplication::shutdown));
    }

    public void shutdown() {
        shutdown.set(true);
    }

    private void read(SelectionKey key) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
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

    private void readOther(Message message, SelectionKey key) {

    }

}
