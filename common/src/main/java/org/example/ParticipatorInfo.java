package org.example;

import lombok.Data;

@Data
public class ParticipatorInfo {
    private Type type;
    private int clientId;

    public enum Type {
        MASTER, WALLET, OTHER,
    }
}
