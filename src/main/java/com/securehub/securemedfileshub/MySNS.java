package com.securehub.securemedfileshub;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;

public class MySNS {

    public static void main(String[] args) {
        try {
            // Argument validation and setup...
            String serverAddress = args[1].split(":")[0];
            int serverPort = Integer.parseInt(args[1].split(":")[1]);
            String command = args[6];
            String doctorUsername = args[3];
            char[] keystorePassword = "doctor".toCharArray(); // Replace with actual keystore password
            String patientUsername = args[5];

            int nOfFilesSent = 0;
            int nOfFilesAlreadyPresent = 0;
            KeyStore keystore = getKeyStore(doctorUsername + ".keystore", keystorePassword);

            try (Socket socket = new Socket(serverAddress, serverPort);
                    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                    DataInputStream dis = new DataInputStream(socket.getInputStream())) {
                dos.writeUTF(command); // Send the command

                // Process files based on the command
                System.out.println("Sending number of files: " + (args.length - 7));
                dos.writeInt(args.length - 7); // Send number of files

                // Send the usernames before the main file loop:

                switch (command) {
                    case "-sc":
                        dos.writeUTF(patientUsername);
                        break;
                    case "-sa":
                        dos.writeUTF(doctorUsername);
                        dos.writeUTF(patientUsername);
                        break;
                    case "-se":
                        dos.writeUTF(doctorUsername);
                        dos.writeUTF(patientUsername);
                        break;
                    case "-g":
              
                    System.out.println("Sending patient username: " + patientUsername);
                    dos.writeUTF(patientUsername); // 2
                        break;
                    default:
                        System.err.println("Unknown command: " + command);
                        dos.writeUTF("Error: Unknown command");
                        break;
                }

                for (int i = 7; i < args.length; i++) {
                    Path file = Paths.get(args[i]);
                    if (!Files.exists(file)) {
                        System.err.println("File not found: " + file);
                        continue;
                    }

                    if ("-sc".equals(command)) {

                        processScCommand(file, dos, keystore, patientUsername);
                    } else if ("-sa".equals(command)) {

                        processSaCommand(file, dos, dis, keystore, keystorePassword, doctorUsername, patientUsername);
                    } else if ("-se".equals(command)) {
                        processSeCommand(file, dos, dis, keystore, keystorePassword, doctorUsername, patientUsername);
                    } else if ("-g".equals(command)) {
                        
                        processGCommand(dis, dos, keystore, patientUsername, args);
                    } else {
                        System.err.println("Unknown command: " + command);
                        dos.writeUTF("Error: Unknown command");
                        continue;
                    }
                    // Here we read the server response for this particular file
                    String serverResponse = dis.readUTF();
                    System.out.println("Resposta server dps do processCommand: " + serverResponse); // Print the
                                                                                                    // server's response

                    if (serverResponse.startsWith("Error:"))
                        nOfFilesAlreadyPresent++;
                    else
                        nOfFilesSent++;

                }
                dos.flush();
                
                if (!"-g".equals(command)) 
                   
             {   String serverResponse = dis.readUTF();
                System.out.println("Resposta server dps do loop: " + serverResponse); // Print the server's response
                System.out.println("Operation complete. " + nOfFilesSent + " files sent, " + nOfFilesAlreadyPresent
                        + " files were already present.");}
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
        
    }

    // Handle -sc command processing
    private static void processScCommand(Path file, DataOutputStream dos, KeyStore keystore, String patientUsername)
            throws Exception {
        SecretKey aesKey = generateAESKey();
        byte[] encryptedFileBytes = encryptFile(Files.readAllBytes(file), aesKey);
        Certificate patientCert = keystore.getCertificate(patientUsername + "cert");
        byte[] encryptedAesKey = encryptAESKey(aesKey, patientCert);
        sendEncryptedFile(dos, file.getFileName().toString(), encryptedFileBytes, patientUsername, encryptedAesKey);
    }

    // Sends encrypted file to the server
    private static void sendEncryptedFile(DataOutputStream dos, String filename, byte[] encryptedFileBytes,
            String patientUsername, byte[] encryptedAesKey) throws IOException {
        dos.writeUTF(filename); // Send base filename
        dos.writeInt(encryptedFileBytes.length); // Send encrypted file length
        dos.write(encryptedFileBytes); // Send encrypted file content

        dos.writeInt(encryptedAesKey.length); // Send encrypted AES key length right after file content
        dos.write(encryptedAesKey); // Send encrypted AES key content
    }

    // Client side: MySNS.java
    private static void processSaCommand(Path file, DataOutputStream dos, DataInputStream dis, KeyStore keystore,
            char[] keystorePassword, String doctorUsername, String patientUsername) throws Exception {
        byte[] fileBytes = Files.readAllBytes(file);
        PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", keystorePassword);
        byte[] signedBytes = signFile(fileBytes, privateKey);

        sendSignedFile(dos, file.getFileName().toString(), fileBytes, signedBytes, doctorUsername);
        dos.flush(); // Flush the DOS to send the file data immediately

    }

    private static void processSeCommand(Path file, DataOutputStream dos, DataInputStream dis, KeyStore keystore,
            char[] keystorePassword, String doctorUsername, String patientUsername) throws Exception {
        SecretKey aesKey = generateAESKey();
        byte[] fileBytes = Files.readAllBytes(file);
        byte[] encryptedFileBytes = encryptFile(fileBytes, aesKey);

        Certificate patientCert = keystore.getCertificate(patientUsername + "cert");
        byte[] encryptedAesKey = encryptAESKey(aesKey, patientCert);

        PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", keystorePassword);
        byte[] signedBytes = signFile(fileBytes, privateKey);

        byte[] signedFileBytes = signFile(encryptedFileBytes, privateKey); // Signing the encrypted file

        sendEncryptedAndSignedFile(dos, file.getFileName().toString(), encryptedFileBytes, encryptedAesKey, signedBytes,
                signedFileBytes, fileBytes, patientUsername, doctorUsername);
        dos.flush(); // Flush the DOS to send the file data immediately
    }

    // Handles the "-g" command: get files from the server
    private static void processGCommand(DataInputStream dis, DataOutputStream dos, KeyStore keystore, String patientUsername, String[] args) throws Exception {
       
        int numberOfFiles = args.length - 7; // Corrected to reflect the actual number of files

        for (int i = 7; i < args.length; i++) { // Corrected to start from the 7th index
            String filename = args[i];
            System.out.println("Requesting file: " + filename);
            dos.writeUTF(filename); // Send the filename to the server
            dos.flush(); // Flush the stream to make sure the data is sent
    
            boolean fileExists = dis.readBoolean(); // Read the response if file exists
            if (!fileExists) {
                System.err.println(filename + " does not exist on the server.");
                continue;
            }
            System.out.println("File "+ filename+ " exists on the server. Receiving file content...");
            
            String fullFilename = dis.readUTF(); // Expecting the full filename

            if (fullFilename.endsWith(".cifrado")) {
                System.out.println("Receiving encrypted file content for: " + filename);
                receiveEncryptedFileAndDecrypt(dis, fullFilename, keystore, patientUsername);
            } else if (fullFilename.endsWith(".assinado")) {
                receiveSignedFileAndVerify(dis, fullFilename, keystore);
            }
        }
    
     

    }
    
    private static void receiveEncryptedFileAndDecrypt(DataInputStream dis, String filename, KeyStore keystore, String patientUsername) throws Exception {
        // Path to save decrypted files
        Path clientDirectory = Paths.get("Client");
        
        // Receive encrypted file content
        int encryptedFileLength = dis.readInt();
        byte[] encryptedFileContent = new byte[encryptedFileLength];
        dis.readFully(encryptedFileContent);
        System.out.println("Received encrypted file content for: " + filename);
       
        KeyStore clientKeystore = getKeyStore(patientUsername + ".keystore", "patient".toCharArray());

        // Receive encrypted AES key
        int encryptedKeyLength = dis.readInt();
        if (encryptedKeyLength > 0) {
            byte[] encryptedAesKey = new byte[encryptedKeyLength];
            dis.readFully(encryptedAesKey);
            System.out.println("Received encrypted AES key for: " + filename);
    
            // Decrypt the AES key using the RSA private key
            printKeystoreAliases(clientKeystore); // Call this method before retrieving the key to see all aliases in the keystore.
            PrivateKey rsaPrivateKey = (PrivateKey) clientKeystore.getKey("patientalias", "patient".toCharArray());
            if (rsaPrivateKey == null) {
                throw new Exception("PrivateKey not found for alias: " + patientUsername + "alias");
            }
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
    
            // Use the decrypted AES key to decrypt the file content
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedFileContent = aesCipher.doFinal(encryptedFileContent);
    
            System.out.println("Decrypted file content for: " + filename);
            // Save the decrypted file content to a new file
            String decryptedFilename = filename.substring(0, filename.lastIndexOf(".cifrado")) + "_decrypted";
            Path decryptedFilePath = clientDirectory.resolve(decryptedFilename);
            Files.write(decryptedFilePath, decryptedFileContent);
            System.out.println("Decrypted file saved as: " + decryptedFilename);
        } else {
            System.err.println("No encrypted AES key received for: " + filename);
        }
    }
    
    
    private static void receiveSignedFileAndVerify(DataInputStream dis, String filename, KeyStore keystore) throws Exception {
        // Path to save signed files
        Path clientDirectory = Paths.get("Client");
    
        // Receive signed file content
        int signedFileLength = dis.readInt();
        byte[] signedFileContent = new byte[signedFileLength];
        dis.readFully(signedFileContent);
        System.out.println("Received signed file content for: " + filename);
    
        // Receive signature
        int signatureLength = dis.readInt();
        byte[] signature = new byte[signatureLength];
        dis.readFully(signature);
        System.out.println("Received signature for: " + filename);
    
        // Verify signature
        PublicKey publicKey = getPublicKeyFromKeystore(keystore, "doctorcert");
        if (verifySignature(signedFileContent, signature, publicKey)) {
            System.out.println("Signature verified successfully for: " + filename);
    
            // Save the signed file content to a new file
            String signedFilename = filename.substring(0, filename.lastIndexOf(".assinado")) + "_verified";
            Path signedFilePath = clientDirectory.resolve(signedFilename);
            Files.write(signedFilePath, signedFileContent);
            System.out.println("Verified signed file saved as: " + signedFilename);
        } else {
            System.err.println("Signature verification failed for: " + filename);
        }
    }
     
    
    // Sends signed file to the server
    private static void sendSignedFile(DataOutputStream dos, String filename, byte[] fileBytes,
            byte[] signature, String doctorUsername) throws IOException {
        dos.writeUTF(filename); // Send base filename
        dos.writeInt(fileBytes.length);
        dos.write(fileBytes);
        dos.writeInt(signature.length); // Send signature length
        dos.write(signature); // Send signature content
    }

    private static void sendEncryptedAndSignedFile(DataOutputStream dos, String filename, byte[] encryptedFileBytes,
            byte[] encryptedAesKey, byte[] signature, byte[] signedFileBytes, byte[] fileBytes, String patientUsername,
            String doctorUsername) throws IOException {
        dos.writeUTF(filename); // Send base filename
        // Send encrypted file
        dos.writeInt(encryptedFileBytes.length);
        dos.write(encryptedFileBytes);
        // Send encrypted AES key
        dos.writeInt(encryptedAesKey.length);
        dos.write(encryptedAesKey);
        dos.writeInt(signedFileBytes.length);
        dos.write(signedFileBytes);

        // Send signature
        dos.writeInt(signature.length);
        dos.write(signature);

        dos.writeInt(fileBytes.length);
        dos.write(fileBytes);
    }

    // Decrypts the file using the provided AES key
    private static byte[] decryptFile(byte[] encryptedData, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        return cipher.doFinal(encryptedData);
    }

    private static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return rsaCipher.doFinal(encryptedData);
    }

    // Verifies the file's signature using the signer's public key
    private static boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    // Retrieves the AES key for a specific file from the keystore
    private static KeyStore getKeyStore(String keystorePath, char[] password) throws Exception {
        // Specify the keystore type if it's not JKS
        KeyStore keystore = KeyStore.getInstance("JKS"); // or "JCEKS" or "PKCS12" as appropriate
        try (InputStream is = new FileInputStream(keystorePath)) {
            keystore.load(is, password);
        }
        return keystore;
    }

    private static SecretKey getAESKeyFromKeystore(KeyStore keystore, String alias, char[] password) {
        try {
            System.out.println("Keystore type: " + keystore.getType());
            System.out.println(
                    "Trying to get key from keystore: " + alias + " with password: " + String.valueOf(password));
            Key key = keystore.getKey(alias, password);
            if (key != null) {
                System.out.println("Key algorithm: " + key.getAlgorithm());
                if (key instanceof SecretKey) {
                    return new SecretKeySpec(key.getEncoded(), "AES");
                } else {
                    System.err.println("Retrieved key is not a SecretKey: " + key.getClass().getName());
                }
            } else {
                System.err.println("No key found in the keystore for the alias: " + alias);
            }
        } catch (Exception e) {
            System.err.println("Failed to get key from keystore. Error: " + e.getMessage());
            e.printStackTrace();
            try {
                printKeystoreAliases(keystore);
            } catch (Exception ex) {
                System.err.println("Failed to print keystore aliases. Error: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
        return null;
    }

    // Retrieves the public key for verifying the signature from the keystore
    private static PublicKey getPublicKeyFromKeystore(KeyStore keystore, String alias) throws Exception {
        Certificate cert = keystore.getCertificate(alias);
        return cert.getPublicKey();
    }

    private static void printKeystoreAliases(KeyStore keystore) throws Exception {
        System.out.println("Keystore contains the following aliases:");
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias in keystore: " + alias);
        }
    }

    // Generates an AES key
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // or 256 for stronger encryption
        return keyGen.generateKey();
    }

    // Encrypts file bytes with an AES key
    private static byte[] encryptFile(byte[] fileBytes, SecretKey aesKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
        return aesCipher.doFinal(fileBytes);
    }

    // Encrypts the AES key with the public RSA key
    private static byte[] encryptAESKey(SecretKey aesKey, Certificate cert) throws Exception {
        PublicKey publicKey = cert.getPublicKey();
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(aesKey.getEncoded());
    }

    // Signs the file using the doctor's private key from the keystore
    private static byte[] signFile(byte[] dataBytes, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(dataBytes);
        return signature.sign();
    }

}
