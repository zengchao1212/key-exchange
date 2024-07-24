package org.example;

import lombok.Data;

import java.security.Key;

@Data
public class ParticipatorInfo {
    private Type type;
    private Key key;

    public enum Type {
        MASTER, WALLET, OTHER,
    }
}
