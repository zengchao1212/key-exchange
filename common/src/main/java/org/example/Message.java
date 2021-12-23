package org.example;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Hex;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;

@Data
@Slf4j
public class Message {

    private final MessageType messageType;
    private final byte[] data;

    private Message(MessageType messageType, byte[] data) {
        this.messageType = messageType;
        this.data = data;
    }

    public static void write(MessageType type, byte[] data, SocketChannel socketChannel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(data.length + 5);
        buffer.put((byte) type.ordinal());
        buffer.putInt(data.length);
        buffer.put(data);
        buffer.rewind();
        socketChannel.write(buffer);
        log.debug("write message:type={},data={}", type.name(), type == MessageType.TEXT ? new String(data, StandardCharsets.UTF_8) : Hex.encodeHexString(data));
    }

    public static Message read(SocketChannel socketChannel) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(5);
        socketChannel.read(buffer);
        buffer.flip();
        MessageType messageType = MessageType.values()[buffer.get()];
        int length = buffer.getInt();
        buffer = ByteBuffer.allocate(length);
        while (buffer.hasRemaining()) {
            socketChannel.read(buffer);
        }
        buffer.flip();
        byte[] data = buffer.array();
        Message message = new Message(messageType, data);
        log.debug("read message:type={},data={}", message.getMessageType().name(), message.getMessageType() == MessageType.TEXT ? new String(data, StandardCharsets.UTF_8) : Hex.encodeHexString(data));
        return message;
    }
}
