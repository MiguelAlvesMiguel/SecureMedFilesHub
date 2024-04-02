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
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class MySNS {

    public static void main(String[] args) {
        try {
            if (args.length < 8 || !"-a".equals(args[0]) || !"-m".equals(args[2]) || !"-u".equals(args[4]) || !"-sc".equals(args[6])) {
                System.err.println("Usage: java MySNSClient -a <serverAddress>:<port> -m <doctorUsername> -u <patientUsername> -sc <filenames>...");
                System.exit(1);
            }

            String serverInfo[] = args[1].split(":");
            String serverAddress = serverInfo[0];
            int serverPort = Integer.parseInt(serverInfo[1]);
            String doctorUsername = args[3];
            String keystorePath = doctorUsername + ".keystore"; // Adjust as needed
            char[] keystorePassword = "doctor".toCharArray(); // Update with the actual password

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keystore.load(fis, keystorePassword);
            }

            Certificate patientCert = keystore.getCertificate("patientcert"); // Adjust alias as necessary
            if (patientCert == null) {
                System.err.println("Certificate for patient not found in keystore.");
                Enumeration<String> aliases = keystore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    System.out.println("Available alias in keystore: " + alias);
                }
                return;
            }
            PublicKey publicKey = patientCert.getPublicKey();

            try (Socket socket = new Socket(serverAddress, serverPort);
                 DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {
                    // Right after establishing the connection to the server:
                dos.writeUTF("-sc"); // Send the command to the server
                dos.writeUTF(args[5]); // Patient username
                dos.writeInt(args.length - 7); // Number of files being sent
                // Continue with sending each file's name, length, and content, followed by the AES key's name, length, and content

                for (int i = 7; i < args.length; i++) {
                    Path file = Paths.get(args[i]);
                    if (!Files.exists(file)) {
                        System.err.println("File does not exist: " + args[i]);
                        continue;
                    }

                    byte[] fileBytes = Files.readAllBytes(file);

                    // AES encryption
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    keyGen.init(128);
                    SecretKey aesKey = keyGen.generateKey();
                    Cipher aesCipher = Cipher.getInstance("AES");
                    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                    byte[] encryptedFileBytes = aesCipher.doFinal(fileBytes);

                    // RSA encryption of the AES key
                    Cipher rsaCipher = Cipher.getInstance("RSA");
                    rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

                    // Send the encrypted file
                    dos.writeUTF(file.getFileName().toString() + ".assinado");
                    dos.writeInt(encryptedFileBytes.length);
                    dos.write(encryptedFileBytes);

                    // Send the encrypted AES key
                    dos.writeUTF(file.getFileName().toString() + ".assinatura." + args[5]);
                    dos.writeInt(encryptedAesKey.length);
                    dos.write(encryptedAesKey);
                }
                dos.flush();
                System.out.println("Encrypted files and keys have been sent.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
