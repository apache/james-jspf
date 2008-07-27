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


package org.apache.james.jspf.core;

/**
 * This interface represent all the macros which can be used in SPF-Records.
 * Read more here : http://www.ietf.org/rfc/rfc4408.txt Section 8
 *  
 */
public interface MacroData {

    /**
     * Get current-senderpart (l)
     * 
     * @return current-senderpart
     */
    public String getCurrentSenderPart();

    /**
     * Get responsible-sender (s)
     * 
     * @return responsible-sender
     */
    public String getMailFrom();

    /**
     * Get sender-domain (h)
     * 
     * @return sender-domain
     */
    public String getHostName();

    /**
     * Get current-domain (d)
     * 
     * @return current-domain
     */
    public String getCurrentDomain();

    /**
     * Get inAddress (v)
     * 
     * @return inAddress
     */
    public String getInAddress();

    /**
     * Get clientDomain (p)
     * 
     * @return clientDomain
     */
    public String getClientDomain();

    /**
     * Get senderDomain (o)
     * 
     * @return senderDomain
     */
    public String getSenderDomain();

    /**
     * Get sending-host (i)
     * 
     * @return sending-host
     */
    public String getMacroIpAddress();

    /**
     * Get timeStamp (t)
     * 
     * @return timeStamp
     */
    public long getTimeStamp();

    /**
     * Get readableIP (c)
     * 
     * @return readableIP
     */
    public String getReadableIP();

    /**
     * Get receivingDomain (r)
     * 
     * @return receivingDomain
     */
    public String getReceivingDomain();

}