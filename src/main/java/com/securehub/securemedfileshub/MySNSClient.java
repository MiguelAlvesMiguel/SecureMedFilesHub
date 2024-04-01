package com.securehub.securemedfileshub;
import java.io.*;
import java.net.*;

public class MySNSClient {
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;

    public MySNSClient(String address, int port) {
        try {
            socket = new Socket(address, port);
            System.out.println("Connected to the server");

            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new PrintWriter(socket.getOutputStream(), true);

        } catch (UnknownHostException ex) {
            System.out.println("Server not found: " + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("I/O error: " + ex.getMessage());
        }
    }

    public void sendFiles() {
        if (socket == null || writer == null) {
            System.out.println("Client is not connected to server");
            return;
        }
        try {
            // Simulate sending file names to the server
            writer.println("file1.txt");
            System.out.println("Client sent file name: file1.txt");
            writer.println("file2.txt");
            System.out.println("Client sent file name: file2.txt");
            writer.println("file3.txt");
            System.out.println("Client sent file name: file3.txt");

            // Signal that we're done sending files
            writer.println("bye");

            // Read the server's responses
            String response;
            while ((response = reader.readLine()) != null) {
                System.out.println(response);
            }

        } catch (IOException ex) {
            System.out.println("I/O error: " + ex.getMessage());
        }
    }

    public void close() {
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException ex) {
            System.out.println("I/O error: " + ex.getMessage());
        }
    }

    public static void main(String[] args) {
        System.out.println("Client started");
        MySNSClient client = new MySNSClient("localhost", 12346);
        client.sendFiles();
        client.close();
    }
}
