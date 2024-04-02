package com.securehub.securemedfileshub;

import java.net.ServerSocket;
import java.net.Socket;
import java.io.DataInputStream;

import java.io.*;

import java.nio.file.Files;

public class MySNSServer {
    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(args[0]); // First argument is the port number
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server started on port " + port);

        while (true) {
            try (Socket socket = serverSocket.accept()) {
                DataInputStream dis = new DataInputStream(socket.getInputStream());

                // Read the username of the patient to determine which directory to save the files
                String patientUsername = dis.readUTF();
                File userDir = new File(patientUsername);
                if (!userDir.exists()) {
                    userDir.mkdir();
                }

                // Read the number of files to expect
                int fileCount = dis.readInt();
                for (int i = 0; i < fileCount; i++) {
                    String fileName = dis.readUTF();
                    int fileLength = dis.readInt();
                    byte[] fileData = new byte[fileLength];
                    dis.readFully(fileData);

                    // Save the encrypted file
                    Files.write(new File(userDir, fileName).toPath(), fileData);

                    // Read and save the encrypted AES key
                    String keyFileName = dis.readUTF();
                    int keyLength = dis.readInt();
                    byte[] keyData = new byte[keyLength];
                    dis.readFully(keyData);
                    Files.write(new File(userDir, keyFileName).toPath(), keyData);
                }

                System.out.println("Files received and saved for patient " + patientUsername);
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
                serverSocket.close();
                e.printStackTrace();
            }
        }
    }
}