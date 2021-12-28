package org.example;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
public class WalletClientApplication extends ClientApplication {
    private String message;

    public WalletClientApplication() throws IOException {
        super(ParticipatorInfo.Type.WALLET);
    }

    public static void main(String[] args) throws IOException {
        ClientApplication.run(new WalletClientApplication());
    }

    @Override
    protected void readEncryptDataCallback(byte[] data) {
        super.readEncryptDataCallback(data);
        message = new String(data, StandardCharsets.UTF_8);
        log.info(message);
    }
}
