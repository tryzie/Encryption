package SymmetricEncryption;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {

        Scanner scanner =new Scanner(System.in);
        System.out.println("Please enter the statement to be encrypted");
        String text = scanner.nextLine();

        //Generate AES key
        KeyGenerator keyGenerator =KeyGenerator.getInstance("AES");

        keyGenerator.init(128); //keysize

        //Secret key
        SecretKey secretKey = keyGenerator.generateKey();

       String code =  Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println(code);

        //AES cipher instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        //start encryption
        byte[] encryptedByte = cipher.doFinal(text.getBytes());


        //Encoding for more readability
        String encryptedText = Base64.getEncoder().encodeToString(encryptedByte);
        System.out.println("Encrypted text is: " + text);
        System.out.println("After the encryption it is: " + encryptedText);


        //Decryption
        //Initialize cipher
        GCMParameterSpec spec =new GCMParameterSpec(128, cipher.getIV());
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        //Start decryption
        byte[] decryptedbyte = cipher.doFinal(Base64.getDecoder().decode(encryptedText));

        String decryptedText = new String(decryptedbyte);
        System.out.println("After decryption it is: " + decryptedText);



    }
}