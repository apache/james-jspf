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

import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.macro.MacroData;

import java.util.HashMap;
import java.util.Map;
import java.util.Stack;

/**
 * 
 * This Class is used as a container between the other classes. All necessary
 * values get stored here and get retrieved from here.
 * 
 */

public class SPFSession implements MacroData {

    private String ipAddress = ""; // also used for (i)<sending-host>

    private String mailFrom = ""; // (s)<responsible-sender>

    private String hostName = ""; // (h)<sender-domain>

    private String currentSenderPart = ""; // (l)

    private String currentDomain = ""; // (d)<current-domain>

    private String inAddress = "in-addr"; // (v)

    private String clientDomain = null; // (p)

    private String senderDomain = ""; // (o)

    private String readableIP = null; // (c)

    private String receivingDomain = null; // (r)

    private int currentDepth = 0;

    /**
     * The maximum mechanismn which are allowed to use
     */
    public static final int MAX_DEPTH = 10;

    private String explanation = null;

    private String currentResult = null;

    private boolean ignoreExplanation = false;
    
    private Map attributes = new HashMap();
    
    private Stack checkers = new Stack();
    
    private Stack catchers = new Stack();

    private String currentResultExpanded;
    
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
    public SPFSession(String mailFrom, String heloDomain, String clientIP) throws PermErrorException, NoneException {
        super();
        this.mailFrom = mailFrom.trim();
        this.hostName = heloDomain.trim();
        this.ipAddress = IPAddr.getProperIpAddress(clientIP.trim());

        try {
            // get the in Address
            this.inAddress = IPAddr.getInAddress(clientIP);
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
        return clientDomain;
    }
    
    /**
     * Sets the calculated clientDomain
     * @param clientDomain the new clientDomain
     */
    public void setClientDomain(String clientDomain) {
        this.clientDomain = clientDomain;
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
            readableIP = IPAddr.getReadableIP(ipAddress);
        }
        return readableIP;
    }

    /**
     * @see org.apache.james.jspf.macro.MacroData#getReceivingDomain()
     */
    public String getReceivingDomain() {
        return receivingDomain;
    }
    
    /**
     * Sets the new receiving domain
     * 
     * @param receivingDomain the new receiving domain
     */
    public void setReceivingDomain(String receivingDomain) {
        this.receivingDomain = receivingDomain;
    }
    
    /**
     * Increase the current depth:
     * 
     * if we reach maximum calls we must throw a PermErrorException. See
     * SPF-RFC Section 10.1. Processing Limits
     */
    public void increaseCurrentDepth() throws PermErrorException {
        this.currentDepth++;
        if (currentDepth > MAX_DEPTH)
            throw new PermErrorException(
                    "Maximum mechanism/modifiers calls done: "
                        + currentDepth);
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
     * Get set to true if the explanation should be ignored
     * 
     * @param ignoreExplanation true or false
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
    
    /**
     * Retrieve a stored attribute
     * 
     * @param key the attribute key
     * @return the stored attribute
     */
    public Object getAttribute(String key) {
        return attributes.get(key);
    }
    
    /**
     * Sets a new attribute in the session
     * 
     * @param key attribute key
     * @param value the value for this attribute
     */
    public void setAttribute(String key, Object value) {
        this.attributes.put(key, value);
    }

    /**
     * @param mechanism
     */
    public void pushChecker(SPFChecker checker) {
        checkers.push(checker);
    }
    
    /**
     * @return the last checker
     */
    public SPFChecker popChecker() {
        if (checkers.isEmpty()) {
            return null;
        } else {
            SPFChecker checker = (SPFChecker) checkers.pop();
            return checker;
        }
    }

    public void pushExceptionCatcher(SPFCheckerExceptionCatcher catcher) {
        catchers.push(catcher);
    }
    
    public SPFCheckerExceptionCatcher popExceptionCatcher() {
        if (catchers.isEmpty()) {
            return null;
        } else {
            return (SPFCheckerExceptionCatcher) catchers.pop();
        }
    }

    public SPFCheckerExceptionCatcher getExceptionCatcher() {
        if (catchers.isEmpty()) {
            return null;
        } else {
            return (SPFCheckerExceptionCatcher) catchers.peek();
        }
    }

    /**
     * @param result
     */
    public void setCurrentResultExpanded(String result) {
        this.currentResultExpanded = result;
    }

    /**
     * @return current result converted/expanded
     */
    public String getCurrentResultExpanded() {
        return currentResultExpanded;
    }

}