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

import org.apache.james.jspf.SPF1Utils;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.macro.MacroData;

import java.util.List;

/**
 * 
 * This Class is used as a container between the other classes. All necessary
 * values get stored here and get retrieved from here.
 * 
 */

public class SPF1Data implements MacroData {

    private DNSService dnsProbe = null;

    protected String spfVersion = "v=spf1";

    private String ipAddress = ""; // also used for (i)<sending-host>

    private String mailFrom = ""; // (s)<responsible-sender>

    private String hostName = ""; // (h)<sender-domain>

    private String currentSenderPart = ""; // (l)

    private String currentDomain = ""; // (d)<current-domain>

    private String inAddress = "in-addr"; // (v)

    private String clientDomain = null; // (p)

    private String senderDomain = ""; // (o)

    private String readableIP = null; // (c)

    private String receivingDomain = "unknown"; // (r)

    private int currentDepth = 0;

    private static final int MAX_DEPTH = 10;

    private String explanation = null;

    private String currentResult = null;

    private boolean match = false;
    
    private boolean ignoreExplanation = false;

    /**
     * Build the SPF1Data from the given parameters
     * 
     * @param mailFrom
     *            The emailaddress of the sender
     * @param heloDomain
     *            The helo provided by the sender
     * @param clientIP
     *            The ipaddress of the client
     * @param dnsProbe
     *            The DNSService
     * @throws PermErrorException
     *             Get thrown if invalid data get passed
     * @throws NoneException
     *             Get thrown if no valid emailaddress get passed
     */
    public SPF1Data(String mailFrom, String heloDomain, String clientIP,
            DNSService dnsProbe) throws PermErrorException, NoneException {
        super();

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
     * @param mailFrom
     *            The emailaddress of the sender
     * @param helo
     *            The provided helo
     * @throws NoneException
     *             Get thrown if an invalid emailaddress get passed
     */
    private void setupData(String mailFrom, String helo) throws NoneException {

        // if nullsender is used postmaster@helo will be used as email
        if (mailFrom.equals("")) {
            this.currentSenderPart = "postmaster";
            this.senderDomain = helo;
            this.mailFrom = currentSenderPart + "@" + helo;
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
        if (clientDomain == null) {
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
     * Get the ipAddress which was used to connect
     * 
     * @return ipAddres 
     */
    public String getIpAddress() {
        return ipAddress;
    }
    
    /**
     * @see org.apache.james.jspf.macro.MacroData#getMacroIpAddress()
     */
    public String getMacroIpAddress() {
        
        if (IPAddr.isIPV6(ipAddress)) {
            try {
                return IPAddr.getAddress(ipAddress).getNibbleFormat();
            } catch (PermErrorException e) {
            }
        } 
        
        return ipAddress;

    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getTimeStamp()
     */
    public long getTimeStamp() {
        return System.currentTimeMillis();
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getReadableIP()
     */
    public String getReadableIP() {
        if (readableIP == null) {
            readableIP = IPAddr.getReadableIP(getIpAddress());
        }
        return readableIP;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getReceivingDomain()
     */
    public String getReceivingDomain() {
        List dNames;

        if (receivingDomain.equals("unknown")) {
            dNames = dnsProbe.getLocalDomainNames();

            for (int i = 0; i < dNames.size(); i++) {
                // check if the domainname is a FQDN
                if (SPF1Utils.checkFQDN(dNames.get(i).toString())) {
                    receivingDomain = dNames.get(i).toString();
                    return receivingDomain;
                }
            }
        }
        return receivingDomain;
    }

    /**
     * Get currentDepth 
     * 
     * @return currentDepth The currentDeph
     */
    public int getCurrentDepth() {
        return currentDepth;
    }

    /**
     * Set currentDepth which is just processed. This will called from
     * modifiers/mechanismn
     * 
     * @param currentDepth
     *            The currentDepth
     */
    public void setCurrentDepth(int currentDepth) {
        this.currentDepth = currentDepth;
    }

    /**
     * Get the maxDepth
     * 
     * @return maxDepth The maximum mechanismn/modifier which are allowed to
     *         proccessed
     */
    public int getMaxDepth() {
        return MAX_DEPTH;
    }

    /**
     * Set the currentDomain
     * 
     * @param domain The current used domain
     */
    public void setCurrentDomain(String domain) {
        this.currentDomain = domain;
    }

    /**
     * Get the used DNSService
     * 
     * @return dnsProbe The DNSService
     */
    public DNSService getDnsProbe() {
        return dnsProbe;
    }

    /**
     * Set the DNSService which will be used
     * 
     * @param dnsProbe The DNSService
     */
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
     * @param result
     *            result
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

    /**
     * Get set if an mechanismn or modifier match
     * 
     * @param match
     *            true or flase
     */
    public void setMatch(boolean match) {
        this.match = match;
    }

    /**
     * Return true if a mechanismn or modifier matched
     * 
     * @return true or false
     */
    public boolean isMatch() {
        return match;
    }
    
    /**
     * Get set to true if the explanation should be ignored
     * 
     * @param ignoreExplanation
     */
    public void setIgnoreExplanation(boolean ignoreExplanation) {
        this.ignoreExplanation = ignoreExplanation; 
    }
    
    /**
     * Return true if the explanation should be ignored
     * 
     * @return true of false
     */
    public boolean ignoreExplanation() {
        return ignoreExplanation;
    }

}