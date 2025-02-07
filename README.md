# Encryption
This shows how you can use AES and RSA to encrypt

Symmetric Encryption
 Encrypt a plain text message using AES-128-GCM. 
 Decrypt the encrypted message to retrieve the original plain text. 


 Asymmetric Encryption/Digital Signatures – I 
 Generate an RSA-2048 key pair (private and public keys). 
 Encrypt a plain text message and then decrypt the encrypted text to retrieve the original 
plain text 
 Sign a plain text message using the private key and verify if it’s correct using the public key. 
 Demonstrate tampering detection by modifying the message and attempting verification.
Task 17: Symmetric & Asymmetric EncrypƟ on – II 
 Generate an AES key using one class, and encrypt it with a public key. Using the same AES 
key, encrypt a random XML string and sign it with the public key. 
 In another class, decrypt the encrypted AES Key using the private key. Using this AES key, 
decrypt the encrypted XML string and check if it has been tampered with by using the 
private key
