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
            // Validation skipped for brevity

            String serverAddress = args[1].split(":")[0];
            int serverPort = Integer.parseInt(args[1].split(":")[1]);
            String command = args[6];
            String doctorUsername = args[3]; // Assumes doctor's username is provided for both -sc and -sa commands
            char[] keystorePassword = "doctor".toCharArray(); // Adjust to actual keystore password

            KeyStore keystore = getKeyStore(doctorUsername + ".keystore", keystorePassword);

            try (Socket socket = new Socket(serverAddress, serverPort);
                 DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {
                dos.writeUTF(command); // Send the command to the server

                if ("-sc".equals(command)) {
                    String patientUsername = args[5]; // Assumes patient's username is provided for -sc command
                    dos.writeUTF(patientUsername); // Send patient username for -sc command
                } else if ("-sa".equals(command)) {
                    dos.writeUTF(doctorUsername); // Send doctor username for -sa command
                }

                dos.writeInt(args.length - 7); // Send the number of files to be processed

                for (int i = 7; i < args.length; i++) {
                    Path file = Paths.get(args[i]);
                    if (!Files.exists(file)) {
                        System.err.println("File not found: " + file);
                        continue;
                    }

                    if ("-sc".equals(command)) {
                        // Encrypt and send file for -sc command
                        SecretKey aesKey = generateAESKey();
                        byte[] encryptedFileBytes = encryptFile(Files.readAllBytes(file), aesKey);
                        Certificate patientCert = keystore.getCertificate(args[5] + "alias"); // Ensure correct alias
                        byte[] encryptedAesKey = encryptAESKey(aesKey, patientCert);
                        sendEncryptedFile(dos, file.getFileName().toString(), encryptedFileBytes, args[5], encryptedAesKey);
                    } else if ("-sa".equals(command)) {
                        // Sign and send file for -sa command
                        byte[] fileBytes = Files.readAllBytes(file);
                        byte[] signedBytes = signFile(fileBytes, (PrivateKey) keystore.getKey(doctorUsername + "alias", keystorePassword)); // Ensure correct alias
                        sendSignedFile(dos, file.getFileName().toString(), fileBytes, signedBytes, doctorUsername);
                    }
                }
                dos.flush();
                System.out.println("Operation complete. Files sent to server.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
    private static void processFile(String filePath, DataOutputStream dos, String command, KeyStore keystore, String doctorUsername, String patientUsername, char[] keystorePassword) throws Exception {
        File file = new File(filePath);
        if (!file.exists()) {
            System.err.println("File not found: " + filePath);
            return;
        }
        byte[] fileBytes = Files.readAllBytes(Paths.get(filePath));

        if ("-sc".equals(command)) {
            SecretKey aesKey = generateAESKey();
            byte[] encryptedFileBytes = encryptFile(fileBytes, aesKey);
            Certificate patientCert = keystore.getCertificate(patientUsername + "alias");
            byte[] encryptedAesKey = encryptAESKey(aesKey, patientCert);
            sendEncryptedFile(dos, file.getName(), encryptedFileBytes, patientUsername, encryptedAesKey);
        } else if ("-sa".equals(command)) {
            PrivateKey privateKey = (PrivateKey) keystore.getKey(doctorUsername + "alias", keystorePassword);
            byte[] signature = signFile(fileBytes, privateKey);
            sendSignedFile(dos, file.getName(), fileBytes, signature, doctorUsername);
        }
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

// Sends encrypted file to the server
private static void sendEncryptedFile(DataOutputStream dos, String filename, byte[] encryptedFileBytes,
                                      String patientUsername, byte[] encryptedAesKey) throws IOException {
    dos.writeUTF(filename + ".cifrado");
    dos.writeInt(encryptedFileBytes.length);
    dos.write(encryptedFileBytes);

    dos.writeUTF(filename + ".chave_secreta." + patientUsername);
    dos.writeInt(encryptedAesKey.length);
    dos.write(encryptedAesKey);
}

// Signs the file using the doctor's private key from the keystore
// Signs the file using the doctor's private key from the keystore
private static byte[] signFile(byte[] dataBytes, PrivateKey privateKey) throws Exception {
    Signature signature = Signature.getInstance("SHA256withRSA");
    signature.initSign(privateKey);
    signature.update(dataBytes);
    return signature.sign();
}


// Sends signed file to the server
private static void sendSignedFile(DataOutputStream dos, String filename, byte[] fileBytes,
                                   byte[] signature, String doctorUsername) throws IOException {
    dos.writeUTF(filename + ".assinado");
    dos.writeInt(fileBytes.length);
    dos.write(fileBytes);

    dos.writeUTF(filename + ".assinatura." + doctorUsername);
    dos.writeInt(signature.length);
    dos.write(signature);
}

}
