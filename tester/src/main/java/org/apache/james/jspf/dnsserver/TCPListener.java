/**************************************************************** 
 * This work is derived from 'jnamed.java' distributed in       *
 * 'dnsjava-2.0.5'. This original is licensed as follows:       *
 * Copyright (c) 1999-2005, Brian Wellington                    *
 * All rights reserved.                                         *
 *                                                              *
 * Redistribution and use in source and binary forms, with or   * 
 * without modification, are permitted provided that the        *  
 * following conditions are met:                                * 
 *                                                              * 
 *  * Redistributions of source code must retain the above      *
 *    copyright notice, this list of conditions and the         *
 *    following disclaimer.                                     *
 *  * Redistributions in binary form must reproduce the above   *
 *    copyright notice, this list of conditions and the         *
 *    following disclaimer in the documentation and/or other    *
 *    materials provided with the distribution.                 *
 *  * Neither the name of the dnsjava project nor the names     *
 *    of its contributors may be used to endorse or promote     *
 *    products derived from this software without specific      *
 *    prior written permission.                                 *
 *                                                              *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND       *
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,  *
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF     *
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE     *
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR         *
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,     *
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR       *
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS         *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF            *
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT    *
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT   *
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE          *
 * POSSIBILITY OF SUCH DAMAGE.                                  *
 *                                                              *
 * Modifications are                                            * 
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