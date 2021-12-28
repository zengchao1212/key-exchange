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
import java.util.ArrayList;
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
    private final int clientCount = 4;
    private final AtomicInteger currentClientCount;
    private final AtomicInteger exchangeTime;
    private final AtomicInteger seq;
    private final AtomicBoolean masterJoin;
    private final AtomicBoolean walletJoin;
    private final PublicKey publicKey;
    private final List<Key> clientKeys;
    private final ServerSocketChannel serverSocketChannel;

    public ServerApplication() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        seq = new AtomicInteger(0);
        currentClientCount = new AtomicInteger(0);
        exchangeTime = new AtomicInteger(0);
        shutdown = new AtomicBoolean(false);
        masterJoin = new AtomicBoolean(false);
        walletJoin = new AtomicBoolean(false);
        selector = Selector.open();
        clientKeys = new CopyOnWriteArrayList<>(new Key[clientCount]);
        KeyPair keyPair = KeyExchange.generate();
        publicKey = keyPair.getPublic();

        serverSocketChannel = ServerSocketChannel.open();
        serverSocketChannel.configureBlocking(false);
        serverSocketChannel.bind(new InetSocketAddress(9553));
    }

    public static void main(String[] argv) {
        ServerApplication serverApplication;
        try {
            serverApplication = new ServerApplication();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("启动失败[{}]", e.getMessage());
            return;
        }

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
                            if (seqId > clientCount) {
                                clientChannel.close();
                                key.cancel();
                                return;
                            }
                            key.attach(seqId);
                            log.info(clientChannel.getRemoteAddress().toString() + " 已连接");
                            clientChannel.configureBlocking(false);
                            Message.write(CLIENT_ID, new byte[]{(byte) seqId}, clientChannel);
                            Message.write(PARTICIPATOR_COUNT, new byte[]{(byte) clientCount}, clientChannel);
                            Message.write(SERVER_PUB, publicKey.getEncoded(), clientChannel);
                            clientChannel.register(selector, SelectionKey.OP_READ);

                        } catch (IOException e) {
                            ParticipatorInfo info = (ParticipatorInfo) key.attachment();
                            if (info != null) {
                                if (info.getType() == ParticipatorInfo.Type.MASTER) {
                                    masterJoin.set(false);
                                } else if (info.getType() == ParticipatorInfo.Type.WALLET) {
                                    walletJoin.set(false);
                                }
                            }
                            currentClientCount.getAndDecrement();
                            log.error(e.getMessage());
                            key.cancel();
                        }
                    }, 1000);
                }
                establishSelector.close();
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
            while (currentClientCount.get() != clientCount) {
                selector.keys().forEach(key -> {
                    SocketChannel client = (SocketChannel) key.channel();
                    try {
                        if (!masterJoin.get()) {
                            Message.write(TEXT, "等待master加入".getBytes(StandardCharsets.UTF_8), client);
                        } else if (!walletJoin.get()) {
                            Message.write(TEXT, "等待wallet加入".getBytes(StandardCharsets.UTF_8), client);
                        } else {
                            String msg = String.format("已有%d位参与者加入,共需%d位参与者", currentClientCount.get(), clientCount);
                            Message.write(TEXT, msg.getBytes(StandardCharsets.UTF_8), client);
                        }
                    } catch (IOException e) {
                        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
                        if (info != null) {
                            if (info.getType() == ParticipatorInfo.Type.MASTER) {
                                masterJoin.set(false);
                            } else if (info.getType() == ParticipatorInfo.Type.WALLET) {
                                walletJoin.set(false);
                            }
                        }
                        log.error(e.getMessage());
                        key.cancel();
                    }
                });
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    log.debug(e.getMessage());
                }
            }
            while (true) {
                long keyCount = clientKeys.stream().filter(Objects::nonNull).count();
                if (keyCount != clientCount) {
                    selector.keys().forEach(key -> {
                        SocketChannel client = (SocketChannel) key.channel();
                        String msg = String.format("第%d轮，已有%d份中间密钥", exchangeTime.get() + 1, currentClientCount.get());
                        try {
                            Message.write(TEXT, msg.getBytes(StandardCharsets.UTF_8), client);
                        } catch (IOException e) {
                            ParticipatorInfo info = (ParticipatorInfo) key.attachment();
                            if (info != null) {
                                if (info.getType() == ParticipatorInfo.Type.MASTER) {
                                    masterJoin.set(false);
                                } else if (info.getType() == ParticipatorInfo.Type.WALLET) {
                                    walletJoin.set(false);
                                }
                            }
                            log.error(e.getMessage());
                            key.cancel();
                        }

                    });
                } else {
                    List<Key> tmpKeys = new ArrayList<>(clientKeys);
                    selector.keys().forEach(key -> {
                        SocketChannel client = (SocketChannel) key.channel();
                        try {
                            ParticipatorInfo keyInfo = (ParticipatorInfo) key.attachment();
                            int clientId = keyInfo.getClientId(), preClientId = clientId - 1;
                            if (preClientId == 0) {
                                preClientId = clientCount;
                            }
                            Key midKey = tmpKeys.get(preClientId - 1);
                            Message.write(MID_KEY, midKey.getEncoded(), client);
                            clientKeys.set(clientId - 1, null);
                        } catch (IOException e) {
                            ParticipatorInfo info = (ParticipatorInfo) key.attachment();
                            if (info != null) {
                                if (info.getType() == ParticipatorInfo.Type.MASTER) {
                                    masterJoin.set(false);
                                } else if (info.getType() == ParticipatorInfo.Type.WALLET) {
                                    walletJoin.set(false);
                                }
                            }
                            log.error(e.getMessage());
                            key.cancel();
                        }
                    });
                    exchangeTime.incrementAndGet();
                }

                if (exchangeTime.get() == clientCount - 1) {
                    break;
                }
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    log.debug(e.getMessage());
                }
            }
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
        } else if (message.getMessageType() == MID_KEY) {
            readMidKey(message, key);
        } else if (message.getMessageType() == ENCRYPT_DATA) {
            readEncryptData(message, key);
        } else {
            readOther(message, key);
        }
    }

    private void readClientType(Message message, SelectionKey key) throws IOException {
        ParticipatorInfo info = new ParticipatorInfo();
        info.setType(ParticipatorInfo.Type.values()[message.getData()[0]]);
        key.attach(info);
        if (message.getData()[0] == ParticipatorInfo.Type.MASTER.ordinal()) {
            if (!masterJoin.compareAndSet(false, true)) {
                key.channel().close();
                key.cancel();
            } else {
                currentClientCount.getAndIncrement();
            }
        } else if (message.getData()[0] == ParticipatorInfo.Type.WALLET.ordinal()) {
            if (!walletJoin.compareAndSet(false, true)) {
                key.channel().close();
                key.cancel();
            } else {
                currentClientCount.getAndIncrement();
            }
        } else {
            currentClientCount.getAndIncrement();
        }
    }

    private void readClientId(Message message, SelectionKey key) {
        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
        int id = message.getData()[0];
        info.setClientId(id);
    }

    private void readMidKey(Message message, SelectionKey key) {
        ParticipatorInfo info = (ParticipatorInfo) key.attachment();
        clientKeys.set(info.getClientId() - 1, KeyExchange.decodeKey(message.getData()));
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
