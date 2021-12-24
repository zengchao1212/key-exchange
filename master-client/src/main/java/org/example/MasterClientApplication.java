package org.example;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@Slf4j
public class MasterClientApplication extends ClientApplication {
    private String data = "大家好，这里是中国";

    public MasterClientApplication() throws IOException {
        super(ParticipatorInfo.Type.MASTER);
    }

    public static void main(String[] args) throws IOException {
        ClientApplication.run(new MasterClientApplication());
    }

}
