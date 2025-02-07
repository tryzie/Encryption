package RSAEncryption;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.UUID;

public class Main {
    public static void main(String[] args) throws  Exception{

//        if (true){
//            System.out.println(UUID.randomUUID().toString());
//            System.out.println(UUID.randomUUID().toString());
//            System.out.println(UUID.randomUUID().toString());
//            System.out.println(UUID.randomUUID().toString());
//            return;
//        }
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter the message to  encrypt");
        String text = scanner.nextLine();


        //Generate key pair(public and private)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); //key size
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        PublicKey publicKey = keyPair.getPublic();
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        //Cipher instance
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);


        byte[] encryptedByte = cipher.doFinal(text.getBytes());

        String encryptedText = Base64.getEncoder().encodeToString(encryptedByte);

        System.out.println("original text is: " + text);

        System.out.println("cipher text is: " + encryptedText);


        //Decryption
        //Initialize cipher
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Start decryption
        byte[] decryptedbyte = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        String decryptedText = new String(decryptedbyte);
        System.out.println("After decryption it is: " + decryptedText);




        //Create a signature object
        Signature signature = Signature.getInstance("SHA256withRSA");

        //initialize signature object
        signature.initSign(privateKey);

        signature.update(text.getBytes());

        byte[] digitalSignatures = signature.sign();

        System.out.println("The digital signature is: " + Base64.getEncoder().encodeToString(digitalSignatures));

        signature.initVerify(publicKey);


        //demonstrates tampering
       // text = "collo";

        signature.update(text.getBytes());

        boolean verified = signature.verify(digitalSignatures);

        if (verified){
            System.out.println("it is verified ");
        } else {
            System.out.println("cannot be verified");
        }


    }
}
