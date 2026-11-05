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

import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Stack;
import java.util.function.Predicate;

/**
 * 
 * This Class is used as a container between the other classes. All necessary
 * values get stored here and get retrieved from here.
 * 
 */

public class SPFSession implements MacroData {

    /**
     * @param s an identity of the SMTP session
     * @return the identity without its leading and trailing spaces and tabs: unlike String.trim, a
     *         control character stays, so that it makes a malformed domain instead of another one
     */
    private static String trimSpaces(String s) {
        int start = 0;
        int end = s.length();
        while (start < end && (s.charAt(start) == ' ' || s.charAt(start) == '\t')) {
            start++;
        }
        while (end > start && (s.charAt(end - 1) == ' ' || s.charAt(end - 1) == '\t')) {
            end--;
        }
        return s.substring(start, end);
    }

    /**
     * @return the name as a domain name, whatever the case and a trailing dot, or null when it is none
     */
    private static Name domainName(String name) {
        try {
            return name == null ? null : Name.fromString(name, Name.root);
        } catch (TextParseException e) {
            return null;
        }
    }

    /**
     * @param validatedNames the validated names of the client address, in the order of its PTR records
     * @param domain the current domain
     * @return %{p}, of RFC 7208 7.3: the domain when it is validated, else the first validated subdomain of it,
     *         else the first validated name, else "unknown"
     */
    private static String clientDomainOf(List<String> validatedNames, String domain) {
        Name target = domainName(domain);
        Optional<String> exact = validatedNames.stream()
            .filter(name -> target != null && target.equals(domainName(name)))
            .findFirst();
        Optional<String> subdomain = validatedNames.stream()
            .filter(name -> target != null && domainName(name) != null && domainName(name).subdomain(target))
            .findFirst();
        return exact.orElse(subdomain.orElse(validatedNames.stream().findFirst().orElse("unknown")));
    }

    private String ipAddress = ""; // also used for (i)<sending-host>

    private String mailFrom = ""; // (s)<responsible-sender>

    private String hostName = ""; // (h)<sender-domain>

    private String currentSenderPart = ""; // (l)

    private String currentDomain = ""; // (d)<current-domain>

    private String inAddress = "invalid"; // (v)

    private String clientDomain = null; // (p)

    private List<String> validatedClientNames = null; // the validated names of (p), once looked up

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
    
    private Map<String,Object> attributes = new HashMap<String,Object>();
    
    private Stack<SPFChecker> checkers = new Stack<SPFChecker>();
    
    private String currentResultExpanded;
    
    /**
     * Build the SPFSession from the given parameters
     * 
     * @param mailFrom
     *            The emailaddress of the sender
     * @param heloDomain
     *            The helo provided by the sender
     * @param clientIP
     *            The ipaddress of the client
     * 
     */
    public SPFSession(String mailFrom, String heloDomain, String clientIP) {
        super();
        if (containsCRLF(mailFrom)) {
            throw new IllegalArgumentException("mailFrom must not contain CR or LF characters");
        }
        if (containsCRLF(heloDomain)) {
            throw new IllegalArgumentException("heloDomain must not contain CR or LF characters");
        }
        this.mailFrom = trimSpaces(mailFrom);
        this.hostName = trimSpaces(heloDomain);
       
        try {
            // an address holds no control character: String.trim gives the same address
            this.ipAddress = IPAddr.getProperIpAddress(clientIP.trim());
            // get the in Address, of the address checked: trimmed, and IPv4 when IPv4-mapped
            this.inAddress = IPAddr.getInAddress(this.ipAddress);
        } catch (PermErrorException e) {
            // ip was not rfc conform
            this.setCurrentResultExpanded(e.getResult());
        }

        // if nullsender is used postmaster@helo will be used as email
        if (this.mailFrom.equals("")) {
            this.currentSenderPart = "postmaster";
            this.senderDomain = hostName;
            this.mailFrom = currentSenderPart + "@" + hostName;
        } else {
            String[] fromParts = this.mailFrom.split("@");
            // What to do when mailFrom is "@example.com" ?
            if (fromParts.length > 1) {
                this.senderDomain = fromParts[fromParts.length -1];
                this.currentSenderPart = this.mailFrom.substring(0, this.mailFrom.length() - senderDomain.length() - 1);
                if (this.currentSenderPart.length() == 0) {
                    this.currentSenderPart = "postmaster";
                }
            } else {
                this.currentSenderPart = "postmaster";
                this.senderDomain = this.mailFrom;
            }
        }
        this.currentDomain = this.senderDomain;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getCurrentSenderPart()
     */
    public String getCurrentSenderPart() {
        return currentSenderPart;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getMailFrom()
     */
    public String getMailFrom() {
        return mailFrom;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getHostName()
     */
    public String getHostName() {
        return hostName;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getCurrentDomain()
     */
    public String getCurrentDomain() {
        return currentDomain;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getInAddress()
     */
    public String getInAddress() {
        return inAddress;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getClientDomain()
     */
    public String getClientDomain() {
        if (clientDomain != null || validatedClientNames == null) {
            return clientDomain;
        }
        // chosen for the current domain, which an include or a redirect changes
        return clientDomainOf(validatedClientNames, getCurrentDomain());
    }

    /**
     * Sets the validated names of the client address, %{p} then being chosen among them for the current domain
     * @param validatedClientNames the validated names, in the order of the PTR records, empty for "unknown"
     */
    void setValidatedClientNames(List<String> validatedClientNames) {
        this.validatedClientNames = validatedClientNames;
    }
    
    /**
     * Sets the calculated clientDomain
     * @param clientDomain the new clientDomain
     */
    public void setClientDomain(String clientDomain) {
        this.clientDomain = clientDomain;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getSenderDomain()
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
     * @see org.apache.james.jspf.core.MacroData#getMacroIpAddress()
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
     * @see org.apache.james.jspf.core.MacroData#getTimeStamp()
     */
    public long getTimeStamp() {
        return System.currentTimeMillis();
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getReadableIP()
     */
    public String getReadableIP() {
        if (readableIP == null) {
            readableIP = IPAddr.getReadableIP(ipAddress);
        }
        return readableIP;
    }

    /**
     * @see org.apache.james.jspf.core.MacroData#getReceivingDomain()
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
     * Remove the attribute stored under the given key
     * 
     * @param key the key of the attribute
     * @return object the attribute which was stored with the key
     */
    public Object removeAttribute(String key) {
        return this.attributes.remove(key);
    }

    /**
     * Add the given SPFChecker on top of the stack
     * 
     * @param checker  
     */
    public void pushChecker(SPFChecker checker) {
        checkers.push(checker);
    }
    
    /**
     * Remove the SPFChecker on the top and return it. If no SPFChecker is left
     * null is returned
     * 
     * @return the last checker
     */
    public SPFChecker popChecker() {
        if (checkers.isEmpty()) {
            return null;
        } else {
            SPFChecker checker = checkers.pop();
            return checker;
        }
    }

    public SPFChecker popChecker(Predicate<SPFChecker> predicate) {
        SPFChecker result = null;
        while (result == null) {
            if (checkers.isEmpty()) {
                return null;
            }
            SPFChecker checker = checkers.pop();
            if (predicate.test(checker)) {
                result = checker;
            }
        }
        return result;
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

    private static boolean containsCRLF(String s) {
        return s.indexOf('\r') >= 0 || s.indexOf('\n') >= 0;
    }

    @Override
    public String toString() {
        return "SPFSession{" +
               "ipAddress='" + ipAddress + '\'' +
               ", mailFrom='" + mailFrom + '\'' +
               ", hostName='" + hostName + '\'' +
               ", currentSenderPart='" + currentSenderPart + '\'' +
               ", currentDomain='" + currentDomain + '\'' +
               ", inAddress='" + inAddress + '\'' +
               ", clientDomain='" + clientDomain + '\'' +
               ", senderDomain='" + senderDomain + '\'' +
               ", readableIP='" + readableIP + '\'' +
               ", receivingDomain='" + receivingDomain + '\'' +
               ", currentDepth=" + currentDepth +
               ", explanation='" + explanation + '\'' +
               ", currentResult='" + currentResult + '\'' +
               ", ignoreExplanation=" + ignoreExplanation +
               ", attributes=" + attributes +
               ", checkers=" + checkers +
               ", currentResultExpanded='" + currentResultExpanded + '\'' +
               '}';
    }
}