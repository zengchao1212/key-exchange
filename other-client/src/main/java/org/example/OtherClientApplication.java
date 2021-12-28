package org.example;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Slf4j
public class OtherClientApplication extends ClientApplication {

    public OtherClientApplication() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        super(ParticipatorInfo.Type.OTHER);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        ClientApplication.run(new OtherClientApplication());
    }

}
