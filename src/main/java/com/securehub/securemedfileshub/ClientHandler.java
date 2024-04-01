package com.securehub.securemedfileshub;
import java.io.*;
import java.net.*;

public class ClientHandler extends Thread {
    private Socket socket;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));

            OutputStream output = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(output, true);

            String text;

            // Example: Read messages from the client and echo them back
            do {
                text = reader.readLine();
                writer.println("Server: " + text);

                // Here you would handle different commands from the client

            } while (!text.equals("bye"));

            socket.close();

        } catch (IOException ex) {
            System.out.println(" clientHandler Server exception: " + ex.getMessage());
            ex.printStackTrace();
        }
    }
}
