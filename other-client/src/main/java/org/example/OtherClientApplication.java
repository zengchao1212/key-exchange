package org.example;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@Slf4j
public class OtherClientApplication extends ClientApplication {

    public OtherClientApplication() throws IOException {
        super(ParticipatorInfo.Type.OTHER);
    }

    public static void main(String[] args) throws IOException {
        ClientApplication.run(new OtherClientApplication());
    }

}
