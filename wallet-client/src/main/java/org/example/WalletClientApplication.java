package org.example;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class WalletClientApplication extends ClientApplication {
    private String data;

    public WalletClientApplication() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        super(ParticipatorInfo.Type.WALLET);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        ClientApplication.run(new WalletClientApplication());
    }
}
