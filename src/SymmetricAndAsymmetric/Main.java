package SymmetricAndAsymmetric;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

public class Main {
    public static void main(String[] args) throws Exception {
        // Generate RSA keypair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Generate AES key
        SecretKey secretKey = Encryption.generateAESKey();

        // Encrypt AES key with RSA
        String encryptedAESKey = Encryption.encryptWithPublicKey(secretKey.getEncoded(), publicKey);

        // XML string
        String xmlString = "<root><data>Hello, Secure World!</data></root>";

        // Encrypt XML with AES-GCM
        String encryptedXML = Encryption.encryptWithAESKey(xmlString, secretKey);

        // Sign encrypted data
        String signature = Encryption.signData(encryptedXML, privateKey);

        System.out.println("Encrypted AES key: " + encryptedAESKey);
        System.out.println("Encrypted XML: " + encryptedXML);
        System.out.println("Signature: " + signature);

        // Decrypt AES key
        SecretKey decryptedAESKey = Decryption.decryptAESKey(encryptedAESKey, privateKey);

        // Decrypt XML
        String decryptedXML = Decryption.decryptWithAESKey(encryptedXML, decryptedAESKey);

        // Verify signature
        boolean isVerified = Decryption.verifyData(encryptedXML, signature, publicKey);

        System.out.println("\nDecrypted XML: " + decryptedXML);
        System.out.println("Signature Verified: " + isVerified);

        if (!isVerified) {
            System.out.println("Warning: The file has been tampered with!");
        } else {
            System.out.println("Success: The XML is verified.");
        }
    }
}
