package com.securehub.securemedfileshub;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.Socket;
import java.io.FileInputStream;
import java.io.DataOutputStream;
import java.security.KeyStore;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.Arrays;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
public class MySNSClient {

    public static void main(String[] args) {
        try {
            if (args.length < 7 || !"-a".equals(args[0]) || !"-m".equals(args[2]) || !"-u".equals(args[4]) || !"-sc".equals(args[6])) {
                System.err.println("Usage: java MySNSClient -a <serverAddress>:<port> -m <doctorUsername> -u <patientUsername> -sc {<filenames>}+");
                System.exit(1);
            }
            System.out.println("Debugging info:");
            Path currentRelativePath = Paths.get("");
            String currentDirectory = currentRelativePath.toAbsolutePath().toString();
            System.out.println("Current working directory: " + currentDirectory);

            File dir = new File(currentDirectory);
            File[] filesList = dir.listFiles();
            System.out.println("Files in the current directory:");
            for (File file : filesList) {
                if (file.isFile()) {
                    System.out.println(file.getName());
                }
            }
            String[] serverInfo = args[1].split(":");
            String serverAddress = serverInfo[0];
            int serverPort = Integer.parseInt(serverInfo[1]);
            //TODO String doctorUsername = args[3];
            String patientUsername = args[5];
            String[] filenames = Arrays.copyOfRange(args, 7, args.length);
            String keystorePath = "doctor.keystore"; // Adjust if your keystore is in a different location
            char[] keystorePassword = "doctor".toCharArray(); // Use the actual keystore password here

            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream keystoreFis = new FileInputStream(keystorePath)) {
                keystore.load(keystoreFis, keystorePassword);
            }

            PublicKey publicKey = keystore.getCertificate("doctoralias").getPublicKey();

            try (Socket socket = new Socket(serverAddress, serverPort);
                 DataOutputStream dos = new DataOutputStream(socket.getOutputStream())) {

                for (String filename : filenames) {
                    if (!Files.exists(Paths.get(filename))) {
                        System.err.println("File not found: " + filename);
                        continue;
                    }

                    byte[] fileContent = Files.readAllBytes(Paths.get(filename));
                    SecretKey aesKey = KeyGenerator.getInstance("AES").generateKey();
                    Cipher aesCipher = Cipher.getInstance("AES");
                    aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                    byte[] encryptedContent = aesCipher.doFinal(fileContent);

                    Cipher rsaCipher = Cipher.getInstance("RSA");
                    rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
                    byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

                    dos.writeUTF(filename + ".cifrado");
                    dos.writeInt(encryptedContent.length);
                    dos.write(encryptedContent);

                    dos.writeUTF(filename + ".chave_secreta." + patientUsername);
                    dos.writeInt(encryptedAesKey.length);
                    dos.write(encryptedAesKey);
                }
                dos.flush();
                System.out.println("Files and keys have been sent to the server.");
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
