/****************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one   *
 * or more contributor license agreements.  See the NOTICE file *
 * distributed with this work for additional information        *
 * regarding copyright ownership.  The ASF licenses this file   *
 * to you under the Apache License, Version 2.0 (the            *
 * "License"); you may not use this file except in compliance   *
 * with the License.  You may obtain a copy of the License at   *
 *                                                              *
 *   http://www.apache.org/licenses/LICENSE-2.0                 *
 *                                                              *
 * Unless required by applicable law or agreed to in writing,   *
 * software distributed under the License is distributed on an  *
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY       *
 * KIND, either express or implied.  See the License for the    *
 * specific language governing permissions and limitations      *
 * under the License.                                           *
 ****************************************************************/

// ATTENTION PLEASE ATTENTION PLEASE ATTENTION PLEASE ATTENTION PLEASE 
// ATTENTION PLEASE ATTENTION PLEASE ATTENTION PLEASE ATTENTION PLEASE  
//
// Part of this class have been inspired and copy&pasted from the jnamed.java
// file found in the root of the dnsjava-2.0.5 distribution file.
//
// The Copyright for the original work is:
// Copyright (c) 1999-2004 Brian Wellington (bwelling@xbill.org)
// 
// The License for the dnsjava-2.0.5 package is BSD  

package org.apache.james.jspf.dnsserver;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public final class UDPListener implements Runnable {

    private final static class UDPResponder implements Runnable {
        private ResponseGenerator responseGenerator;

        private DatagramSocket sock;
        private InetAddress addr;
        private int port;
        private byte[] in;

        private UDPResponder(DatagramSocket sock, InetAddress addr, int port, byte[] in, ResponseGenerator rg) {
            this.sock = sock;
            this.addr = addr;
            this.port = port;
            this.in = in;
            this.responseGenerator = rg;
        }

        public void run() {
            try {
                DatagramPacket outdp = null;
                byte[] response = responseGenerator.generateReply(in, in.length);
                if (response == null)
                    return;
                if (outdp == null) {
                    outdp = new DatagramPacket(response, response.length,
                            addr, port);
                } else {
                    outdp.setData(response);
                    outdp.setLength(response.length);
                    outdp.setAddress(addr);
                    outdp.setPort(port);
                }
                sock.send(outdp);
            } catch (IOException e) {
                System.out.println("UDPResponder(" + addr.getHostAddress() + "#" + port + "): "
                        + e);
            }
        }

    }


    
    private final InetAddress addr;

    private final int port;

    private ResponseGenerator responseGenerator;

    UDPListener(InetAddress addr, int port, ResponseGenerator rg) {
        this.addr = addr;
        this.port = port;
        this.responseGenerator = rg;
    }

    public void run() {
        try {
            DatagramSocket sock = new DatagramSocket(port, addr);
            final short udpLength = 512;
            byte[] in = new byte[udpLength];
            DatagramPacket indp = new DatagramPacket(in, in.length);
            while (true) {
                indp.setLength(in.length);
                try {
                    sock.receive(indp);
                } catch (InterruptedIOException e) {
                    continue;
                }

                byte[] local = new byte[indp.getLength()];
                System.arraycopy(in, 0, local, 0, indp.getLength());
                Runnable runnable = new UDPResponder(sock, indp.getAddress(), indp.getPort(), local, responseGenerator);
                
                new Thread(runnable).start();
            }
        } catch (IOException e) {
            System.out.println("UDPListener(" + addr.getHostAddress() + "#" + port + "): "
                    + e);
        }
    }

}