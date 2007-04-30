// ATTENTION PLEASE ATTENTION PLEASE ATTENTION PLEASE ATTENTION PLEASE 
// ATTENTION PLEASE ATTENTION PLEASE ATTENTION PLEASE ATTENTION PLEASE  
//
// Part of this class have been inspired and copy&pasted from the jnamed.java
// file found in the root of the dnsjava-2.0.3 distribution file.
//
// The Copyright for the original work is:
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)
// 
// The License for the dnsjava-2.0.3 package is BSD  

package org.apache.james.jspf.dnsserver;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

public final class TCPListener implements Runnable {
    
    private final static class TCPServer implements Runnable {
        private final Socket serverSocket;

        private ResponseGenerator responseGenerator;

        private TCPServer(Socket s, ResponseGenerator rg) {
            this.serverSocket = s;
            this.responseGenerator = rg;
        }

        public void run() {
            try {
                int inLength;
                DataInputStream dataIn;
                DataOutputStream dataOut;
                byte[] in;

                InputStream is = serverSocket.getInputStream();
                dataIn = new DataInputStream(is);
                inLength = dataIn.readUnsignedShort();
                in = new byte[inLength];
                dataIn.readFully(in);

                int length = in.length;
                byte[] response = responseGenerator.generateReply(in, length);
                if (response == null) return;
                dataOut = new DataOutputStream(serverSocket.getOutputStream());
                dataOut.writeShort(response.length);
                dataOut.write(response);
            } catch (IOException e) {
                System.out.println("TCPclient("
                        + serverSocket.getLocalAddress().getHostAddress() + "#" + serverSocket.getLocalPort()
                        + "): " + e);
            } finally {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                }
            }
        }

    }

    private final int port;

    private final InetAddress addr;

    private ResponseGenerator responseGenerator;

    public TCPListener(InetAddress addr, int port, ResponseGenerator rg) {
        this.port = port;
        this.addr = addr;
        this.responseGenerator = rg;
    }

    public void run() {
        try {
            ServerSocket sock = new ServerSocket(port, 128, addr);
            while (true) {
                new Thread(new TCPServer(sock.accept(), responseGenerator)).start();
            }
        } catch (IOException e) {
            System.out.println("serveTCP(" + addr.getHostAddress() + "#" + port + "): "
                    + e);
        }
    }
}