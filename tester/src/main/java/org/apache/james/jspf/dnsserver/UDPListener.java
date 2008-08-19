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