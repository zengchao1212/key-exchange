package org.example;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class KeyExchange {
    static {
        try {
            Security.insertProviderAt((Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
                    .getDeclaredConstructor().newInstance(), 1);
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    public static KeyPair generate() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
        return generator.generateKeyPair();
    }

    public static KeyPair generate(PublicKey serverPubKey) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        AlgorithmParameterSpec parameterSpec = ((DHPublicKey) serverPubKey).getParams();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
        generator.initialize(parameterSpec);
        return generator.generateKeyPair();
    }

    public static PublicKey decodePublicKey(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(data);
        return keyFactory.generatePublic(x509KeySpec);
    }

    public static Key decodeKey(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(data);
        return keyFactory.generatePublic(x509KeySpec);
    }

    public static KeyAgreement getKeyAgreement() throws NoSuchAlgorithmException, InvalidKeyException {
        return KeyAgreement.getInstance("DH");
    }

    public static Key generateMiddleKey(KeyAgreement keyAgreement, PrivateKey privateKey, PublicKey publicKey, boolean lastPhase) throws NoSuchAlgorithmException, InvalidKeyException {
        keyAgreement.init(privateKey);
        return keyAgreement.doPhase(publicKey, lastPhase);
    }

    public static SecretKey generateSecretKey(KeyAgreement keyAgreement) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException {
        return new SecretKeySpec(keyAgreement.generateSecret(), 0, 16, "AES");
    }

    public static byte[] encrypt(SecretKey secretKey, byte[] data) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(SecretKey secretKey, byte[] data) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }
}
