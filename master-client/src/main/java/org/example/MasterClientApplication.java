package org.example;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class MasterClientApplication extends ClientApplication {
    private String data = "大家好，这里是中国";

    public MasterClientApplication() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        super(ParticipatorInfo.Type.MASTER);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        ClientApplication.run(new MasterClientApplication());
    }

    @Override
    protected void afterExchange() throws Exception {
        super.afterExchange();
        Message.write(MessageType.ENCRYPT_DATA, KeyExchange.encrypt(secretKey, data.getBytes(StandardCharsets.UTF_8)), socketChannel);
    }
}
