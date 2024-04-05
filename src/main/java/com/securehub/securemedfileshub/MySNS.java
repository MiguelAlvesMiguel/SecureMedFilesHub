package com.securehub.securemedfileshub;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
            String patientUsername = ""; // Will be set later based on command

            int nOfFilesSent = 0;
            int nOfFilesAlreadyPresent = 0;
            KeyStore keystore = getKeyStore(doctorUsername + ".keystore", keystorePassword);

            try (Socket socket = new Socket(serverAddress, serverPort);
                    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                    DataInputStream dis = new DataInputStream(socket.getInputStream())) {
                dos.writeUTF(command); // Send the command

                // Determine which username to send based on the command
                if ("-sc".equals(command)) {
                    patientUsername = args[5];
                    dos.writeUTF(patientUsername); // For -sc, send patient username
                } else if ("-sa".equals(command)) {
                    patientUsername = args[5]; // This might need adjustment depending on your logic
                    dos.writeUTF(doctorUsername); // For -sa, send doctor username
                    dos.writeUTF(patientUsername); // And then send patient username
                }

                // Process files based on the command
                dos.writeInt(args.length - 7); // Number of files
                for (int i = 7; i < args.length; i++) {
                    Path file = Paths.get(args[i]);
                    if (!Files.exists(file)) {
                        System.err.println("File not found: " + file);
                        continue;
                    }

                   
                     if ("-sc".equals(command)) {
                         processScCommand(file, dos, keystore, patientUsername);
                     } else if ("-sa".equals(command)) {
                         processSaCommand(file, dos, keystore, keystorePassword, doctorUsername, patientUsername);
                     }
                     // Here we read the server response for this particular file
                     String serverResponse = dis.readUTF();
                     System.out.println(serverResponse); // Print the server's response

                     if (serverResponse.startsWith("Error:"))
                         nOfFilesAlreadyPresent++;
                     else
                         nOfFilesSent++;

                }
                dos.flush();

                System.out.println("Operation complete. " + nOfFilesSent + " files sent, " + nOfFilesAlreadyPresent
                        + " files were already present.");
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

    private static void processSaCommand(Path file, DataOutputStream dos, KeyStore keystore,
    char[] keystorePassword, String doctorUsername,
    String patientUsername) throws Exception {
byte[] fileBytes = Files.readAllBytes(file);
PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", keystorePassword);
byte[] signedBytes = signFile(fileBytes, privateKey);

sendSignedFile(dos, file.getFileName().toString(), fileBytes, signedBytes, doctorUsername);
// The response reading will happen after this method in the main loop
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

    private static KeyStore getKeyStore(String keystorePath, char[] password) throws Exception {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream is = new FileInputStream(keystorePath)) {
            keystore.load(is, password);
        }
        return keystore;
    }

    private static void printKeystoreAliases(KeyStore keystore) throws Exception {
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
