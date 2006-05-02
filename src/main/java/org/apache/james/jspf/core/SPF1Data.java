/**********************************************************************
 * Copyright (c) 2006 The Apache Software Foundation.             *
 * All rights reserved.                                                *
 * ------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License"); you *
 * may not use this file except in compliance with the License. You    *
 * may obtain a copy of the License at:                                *
 *                                                                     *
 *     http://www.apache.org/licenses/LICENSE-2.0                      *
 *                                                                     *
 * Unless required by applicable law or agreed to in writing, software *
 * distributed under the License is distributed on an "AS IS" BASIS,   *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or     *
 * implied.  See the License for the specific language governing       *
 * permissions and limitations under the License.                      *
 ***********************************************************************/

package org.apache.james.jspf.core;

import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.macro.MacroData;
import org.apache.james.jspf.util.IPAddr;

import java.util.List;

/**
 * 
 * This Class is used as a Container between the other classes.
 * 
 * @author Mimecast Contact : spf@mimecast.net
 * @author Norman Maurer <nm@byteaction.de>
 */

public class SPF1Data implements MacroData {

    private DNSService dnsProbe = null;

    protected String spfVersion = "v=spf1";

    
    private String ipAddress = ""; // (i)<sending-host>

    private String mailFrom = ""; // (s)<responsible-sender>

    private String hostName = ""; // (h)<sender-domain>

    private String currentSenderPart = ""; // (l)

    private String currentDomain = ""; // (d)<current-domain>

    private String inAddress = "in-addr"; // (v)

    private String clientDomain = ""; // (p)

    private String senderDomain = ""; // (o)

    private long timeStamp = System.currentTimeMillis(); // (t)

    private String readableIP = ""; // (c)

    private String receivingDomain = "unknown"; // (r)
    

    private int currentDepth = 0;
    
    private int maxDepth = 10;

    private String explanation = "";

    private String currentResult = null;

    private boolean match = false;

    public SPF1Data(String mailFrom, String heloDomain, String clientIP,
            DNSService dnsProbe) throws PermErrorException, NoneException {

        this.mailFrom = mailFrom.trim();
        this.hostName = heloDomain.trim();
        this.ipAddress = clientIP.trim();
        this.dnsProbe = dnsProbe;

        try {
            // get the in Address
            inAddress = IPAddr.getInAddress(clientIP);
        } catch (PermErrorException e) {
            // throw an exception cause the ip was not rfc conform
            throw new PermErrorException(e.getMessage());
        }

        // setup the data!
        setupData(mailFrom, hostName);
    }

    /**
     * Setup the data which used to retrieve the SPF-Record
     * 
     * @throws NoneException
     *             if no valid emailaddress is provided
     */
    private void setupData(String mailFrom, String hostName)
            throws NoneException {

        // if nullsender is used postmaster@helo will be used as email
        if (mailFrom.equals("")) {
            this.currentSenderPart = "postmaster";
            this.senderDomain = hostName;
            this.mailFrom = currentSenderPart + "@" + hostName;
        } else {
            String[] fromParts = mailFrom.split("@");

            // should never be bigger as 2 !
            if (fromParts.length > 2) {
                throw new NoneException("Not a valid email address " + mailFrom);
            } else if (fromParts.length == 2) {
                this.currentSenderPart = fromParts[0];
                this.senderDomain = fromParts[1];
            } else {
                this.currentSenderPart = "postmaster";
                this.senderDomain = mailFrom;
            }
        }
        this.currentDomain = this.senderDomain;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getCurrentSenderPart()
     */
    public String getCurrentSenderPart() {
        return currentSenderPart;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getMailFrom()
     */
    public String getMailFrom() {
        return mailFrom;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getHostName()
     */
    public String getHostName() {
        return hostName;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getCurrentDomain()
     */
    public String getCurrentDomain() {
        return currentDomain;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getInAddress()
     */
    public String getInAddress() {
        return inAddress;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getClientDomain()
     */
    public String getClientDomain() {
        List domains;
        try {
            domains = dnsProbe.getPTRRecords(ipAddress);
            if (domains.size() > 0) {
                clientDomain = (String) domains.get(0);
            } else {
                clientDomain = ipAddress;
            }
        } catch (Exception e) {
            clientDomain = ipAddress;
        }
        return clientDomain;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getSenderDomain()
     */
    public String getSenderDomain() {
        return senderDomain;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getIpAddress()
     */
    public String getIpAddress() {
        return ipAddress;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getTimeStamp()
     */
    public long getTimeStamp() {
        return timeStamp;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getReadableIP()
     */
    public String getReadableIP() {
        return readableIP;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getReceivingDomain()
     */
    public String getReceivingDomain() {
        return receivingDomain;
    }

    /**
     * Get currentDepth
     * 
     * @return currentDepth
     */
    public int getCurrentDepth() {
        return currentDepth;
    }

    /**
     * Set currentDepth
     * 
     * @param currentDepth
     */
    public void setCurrentDepth(int currentDepth) {
        this.currentDepth = currentDepth;
    }
    
    /**
     * Get the maxDepth
     * 
     * @return maxDepth
     */
    public int getMaxDepth() {
        return maxDepth;
    }

    /**
     * Set the currentDomain
     * 
     * @param domain
     */
    public void setCurrentDomain(String domain) {
        this.currentDomain = domain;
    }

    public DNSService getDnsProbe() {
        return dnsProbe;
    }

    public void setDnsProbe(DNSService dnsProbe) {
        this.dnsProbe = dnsProbe;
    }

    /**
     * Set the explanation which will returned when a fail match
     * 
     * @param explanation
     *            This String is set as explanation
     */
    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    /**
     * Get the explanation
     * 
     * @return explanation
     */
    public String getExplanation() {
        return explanation;
    }

    /**
     * Set the current result
     * 
     * @param result result
     */
    public void setCurrentResult(String result) {
        this.currentResult = result;
    }

    /**
     * Get the current result
     * 
     * @return current result
     */
    public String getCurrentResult() {
        return currentResult;
    }

    public void setMatch(boolean match) {
        this.match = match;
    }

    public boolean isMatch() {
        return match;
    }

}