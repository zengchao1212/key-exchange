package org.example;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@Slf4j
public class WalletClientApplication extends ClientApplication {
    private String data;

    public WalletClientApplication() throws IOException {
        super(ParticipatorInfo.Type.WALLET);
    }

    public static void main(String[] args) throws IOException {
        ClientApplication.run(new WalletClientApplication());
    }
}
