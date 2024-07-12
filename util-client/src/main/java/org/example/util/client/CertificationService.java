package org.example.util.client;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.*;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

public class CertificationService {

    private static void write(Path file, List<String> lines) {
        try (PrintWriter writer = new PrintWriter(file.toFile())) {
            lines.forEach(writer::println);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void genCaRootPriAndCert(Path priPath, Path certPath) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException {
        Files.createDirectories(priPath.getParent());
        Files.createDirectories(certPath.getParent());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        List<String> priLines = new ArrayList<>();
        priLines.add("-----BEGIN PRIVATE KEY-----");
        priLines.add(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        priLines.add("-----END PRIVATE KEY-----");
        write(priPath, priLines);

        PublicKey publicKey = keyPair.getPublic();
        X500Name issuer = new X500Name("CN=CA-ROOT, OU=IT Department, O=Example.org, L=HK, C=CN");
        byte[] rand = new byte[32];
        new SecureRandom().nextBytes(rand);
        BigInteger serialNo = new BigInteger(1, rand);
        Date notBefore = Date.from(LocalDateTime.now().atZone(ZoneOffset.systemDefault()).toInstant());
        Date notAfter = Date.from(LocalDateTime.now().plusYears(100).atZone(ZoneOffset.systemDefault()).toInstant());
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serialNo, notBefore, notAfter, issuer, publicKey);
        ContentSigner contentSigner = new JcaContentSignerBuilder("Ed25519").build(privateKey);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
        String certString = Base64.getEncoder().encodeToString(certificate.getEncoded());
        List<String> certLines = new ArrayList<>();
        certLines.add("-----BEGIN CERTIFICATE-----");
        for (int i = 0; i < certString.length(); ) {
            int start = i;
            int end = Math.min(start + 64, certString.length());
            String line = certString.substring(start, end);
            certLines.add(line);
            i = end;
        }
        certLines.add("-----END CERTIFICATE-----");
        write(certPath, certLines);
    }

    public static void genCaRootCertWithPri(Path priPath, Path certPath) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, InvalidKeySpecException {
        Files.createDirectories(certPath.getParent());

        List<String> priLines = Files.readAllLines(priPath);
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(priLines.get(1)));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        Ed25519PrivateKeyParameters privateKeyParameters = new Ed25519PrivateKeyParameters(((EdECPrivateKey) privateKey).getBytes().get());
        Ed25519PublicKeyParameters publicKeyParameters = privateKeyParameters.generatePublicKey();
        byte[] data = publicKeyParameters.getEncoded();
        boolean isOdd = data[31] < 0;
        data[31] = (byte) (data[31] & 0b01111111);
        for (int i = 0; i < 16; i++) {
            byte t = data[i];
            data[i] = data[31 - i];
            data[31 - i] = t;
        }
        EdECPublicKeySpec publicKeySpec = new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(isOdd, new BigInteger(1, data)));
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        X500Name issuer = new X500Name("CN=CA-ROOT, OU=IT Department, O=Example.org, L=HK, C=CN");
        byte[] rand = new byte[32];
        new SecureRandom().nextBytes(rand);
        BigInteger serialNo = new BigInteger(1, rand);
        Date notBefore = Date.from(LocalDateTime.now().atZone(ZoneOffset.systemDefault()).toInstant());
        Date notAfter = Date.from(LocalDateTime.now().plusYears(100).atZone(ZoneOffset.systemDefault()).toInstant());
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serialNo, notBefore, notAfter, issuer, publicKey);
        ContentSigner contentSigner = new JcaContentSignerBuilder("Ed25519").build(privateKey);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
        String certString = Base64.getEncoder().encodeToString(certificate.getEncoded());
        List<String> certLines = new ArrayList<>();
        certLines.add("-----BEGIN CERTIFICATE-----");
        for (int i = 0; i < certString.length(); ) {
            int start = i;
            int end = Math.min(start + 64, certString.length());
            String line = certString.substring(start, end);
            certLines.add(line);
            i = end;
        }
        certLines.add("-----END CERTIFICATE-----");
        write(certPath, certLines);
    }

    public static void genPriAndPub(Path priPath, Path pubPath) throws NoSuchAlgorithmException, IOException {
        Files.createDirectories(priPath.getParent());
        Files.createDirectories(pubPath.getParent());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        List<String> priLines = new ArrayList<>();
        priLines.add("-----BEGIN PRIVATE KEY-----");
        priLines.add(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        priLines.add("-----END PRIVATE KEY-----");
        write(priPath, priLines);

        PublicKey publicKey = keyPair.getPublic();
        List<String> pubLines = new ArrayList<>();
        pubLines.add("-----BEGIN PUBLIC KEY-----");
        pubLines.add(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        pubLines.add("-----END PUBLIC KEY-----");
        write(pubPath, pubLines);
    }

    public static void genPriAndCsr(Path priPath, Path csrPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, OperatorCreationException {
        Files.createDirectories(priPath.getParent());
        Files.createDirectories(csrPath.getParent());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        List<String> priLines = new ArrayList<>();
        priLines.add("-----BEGIN PRIVATE KEY-----");
        priLines.add(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        priLines.add("-----END PRIVATE KEY-----");
        write(priPath, priLines);

        PublicKey publicKey = keyPair.getPublic();
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=Gen-Key, OU=IT Department, O=Example.org, L=HK, C=CN"), publicKey);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("Ed25519");
        ContentSigner signer = csBuilder.build(privateKey);
        PKCS10CertificationRequest csr = p10Builder.build(signer);
        String csrString = Base64.getEncoder().encodeToString(csr.getEncoded());
        List<String> csrLines = new ArrayList<>();
        csrLines.add("-----BEGIN CERTIFICATE REQUEST-----");
        for (int i = 0; i < csrString.length(); ) {
            int start = i;
            int end = Math.min(start + 64, csrString.length());
            String line = csrString.substring(start, end);
            csrLines.add(line);
            i = end;
        }
        csrLines.add("-----END CERTIFICATE REQUEST-----");
        write(csrPath, csrLines);
    }

    public static void genCert(Path caPriPath, Path csrPath, Path certPath) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, OperatorCreationException, CertificateException {
        Files.createDirectories(caPriPath.getParent());
        Files.createDirectories(certPath.getParent());
        List<String> priLines = Files.readAllLines(caPriPath);
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(priLines.get(1)));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        X500Name issuer = new X500Name("CN=CA, OU=IT Department, O=Example.org, L=HK, C=CN");
        byte[] rand = new byte[32];
        new SecureRandom().nextBytes(rand);
        BigInteger serialNo = new BigInteger(1, rand);
        Date notBefore = Date.from(LocalDateTime.now().atZone(ZoneOffset.systemDefault()).toInstant());
        Date notAfter = Date.from(LocalDateTime.now().plusYears(100).atZone(ZoneOffset.systemDefault()).toInstant());
        List<String> csrLines = Files.readAllLines(csrPath);
        StringBuilder csrString = new StringBuilder();
        for (int i = 1; i < csrLines.size() - 1; i++) {
            csrString.append(csrLines.get(i));
        }
        CertificationRequest csrRequest = CertificationRequest.getInstance(ASN1Primitive.fromByteArray(Base64.getDecoder().decode(csrString.toString())));
        byte[] pubKeyBs = csrRequest.getCertificationRequestInfo().getSubjectPublicKeyInfo().getEncoded();
        keySpec = new X509EncodedKeySpec(pubKeyBs);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serialNo, notBefore, notAfter, csrRequest.getCertificationRequestInfo().getSubject(), publicKey);
        ContentSigner contentSigner = new JcaContentSignerBuilder("Ed25519").build(privateKey);
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
        String certString = Base64.getEncoder().encodeToString(certificate.getEncoded());
        List<String> certLines = new ArrayList<>();
        certLines.add("-----BEGIN CERTIFICATE-----");
        for (int i = 0; i < certString.length(); ) {
            int start = i;
            int end = Math.min(start + 64, certString.length());
            String line = certString.substring(start, end);
            certLines.add(line);
            i = end;
        }
        certLines.add("-----END CERTIFICATE-----");
        write(certPath, certLines);
    }

    public static boolean verify(Path caCerPath, Path cerPath) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<String> lines = Files.readAllLines(cerPath);
        StringBuilder cerString = new StringBuilder();
        for (int i = 1; i < lines.size() - 1; i++) {
            cerString.append(lines.get(i));
        }
        ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(cerString.toString()));
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(in);
        try {
            certificate.checkValidity();
        } catch (RuntimeException e) {
            return false;
        }
        byte[] sig = certificate.getSignature();
        byte[] data = certificate.getTBSCertificate();

        lines = Files.readAllLines(caCerPath);
        cerString = new StringBuilder();
        for (int i = 1; i < lines.size() - 1; i++) {
            cerString.append(lines.get(i));
        }
        in = new ByteArrayInputStream(Base64.getDecoder().decode(cerString.toString()));
        certificate = (X509Certificate) certificateFactory.generateCertificate(in);

        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(certificate);
        signature.update(data);
        return signature.verify(sig);
    }

}
