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
 * This Class is used to convert all macros which can used in SPF-Records to the
 * right values!
 * 
 */

import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.TempErrorException;
import org.apache.james.jspf.core.exceptions.TimeoutException;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MacroExpand {

    private Pattern domainSpecPattern;

    private Pattern macroStringPattern;

    private Pattern macroLettersPattern;

    private Pattern macroLettersExpPattern;

    private Pattern cellPattern;

    private Logger log;

    private DNSService dnsProbe;

    public static final boolean EXPLANATION = true;
    
    public static final boolean DOMAIN = false;
    
    public static class RequireClientDomainException extends Exception {

        private static final long serialVersionUID = 3834282981657676530L;
        
    }

    /**
     * Construct MacroExpand
     * 
     * @param logger the logget to use
     * @param dnsProbe the dns service to use
     */
    public MacroExpand(Logger logger, DNSService dnsProbe) {
        // This matches 2 groups
        domainSpecPattern = Pattern.compile(SPFTermsRegexps.DOMAIN_SPEC_REGEX_R);
        // The real pattern replacer
        macroStringPattern = Pattern.compile(SPFTermsRegexps.MACRO_STRING_REGEX_TOKEN);
        // The macro letters pattern
        macroLettersExpPattern = Pattern.compile(SPFTermsRegexps.MACRO_LETTER_PATTERN_EXP);
        macroLettersPattern = Pattern.compile(SPFTermsRegexps.MACRO_LETTER_PATTERN);
        log = logger;
        this.dnsProbe = dnsProbe;
    }
    

    private static final class AResponseListener implements
            SPFCheckerDNSResponseListener {
        
        /**
         * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation onDNSResponse(DNSResponse response, SPFSession session)
                throws PermErrorException, NoneException, TempErrorException,
                NeutralException {
            // just return the default "unknown" if we cannot find anything
            // later
            session.setClientDomain("unknown");
            try {
                List<String> records = response.getResponse();
                if (records != null && records.size() > 0) {
                    Iterator<String> i = records.iterator();
                    while (i.hasNext()) {
                        String next = i.next();
                        if (IPAddr.getAddress(session.getIpAddress())
                                .toString().equals(
                                        IPAddr.getAddress(next).toString())) {
                            session
                                    .setClientDomain((String) session
                                            .getAttribute(ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD));
                            break;
                        }
                    }
                }
            } catch (TimeoutException e) {
                // just return the default "unknown".
            } catch (PermErrorException e) {
                // just return the default "unknown".
            }
            return null;
        }
    }

    private static final class PTRResponseListener implements
            SPFCheckerDNSResponseListener {

        /**
         * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation onDNSResponse(DNSResponse response, SPFSession session)
                throws PermErrorException, NoneException, TempErrorException,
                NeutralException {

            try {
                boolean ip6 = IPAddr.isIPV6(session.getIpAddress());
                List<String> records = response.getResponse();

                if (records != null && records.size() > 0) {
                    String record = records.get(0);
                    session.setAttribute(ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD,
                            record);

                    return new DNSLookupContinuation(new DNSRequest(record,
                            ip6 ? DNSRequest.AAAA : DNSRequest.A), 
                            new AResponseListener());

                }
            } catch (TimeoutException e) {
                // just return the default "unknown".
            }
                    
            session.setClientDomain("unknown");        
            return null;

        }
    }

    private static final String ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD = "MacroExpand.checkedRecord";

    public DNSLookupContinuation checkExpand(String input, SPFSession session, boolean isExplanation) throws PermErrorException, NoneException {
        if (input != null) {
            String host = this.expand(input, session, isExplanation);
            if (host == null) {

                return new DNSLookupContinuation(new DNSRequest(IPAddr
                        .getAddress(session.getIpAddress()).getReverseIP(),
                        DNSRequest.PTR), new PTRResponseListener());
            }
        }
        return null;
    }
    
    public String expand(String input, MacroData macroData, boolean isExplanation) throws PermErrorException {
        try {
            if (isExplanation) {
                return expandExplanation(input, macroData);
            } else {
                return expandDomain(input, macroData);
            }
        } catch (RequireClientDomainException e) {
            return null;
        }
    }

    /**
     * This method expand the given a explanation
     * 
     * @param input
     *            The explanation which should be expanded
     * @return expanded The expanded explanation
     * @throws PermErrorException
     *             Get thrown if invalid macros are used
     * @throws RequireClientDomain 
     */
    private String expandExplanation(String input, MacroData macroData) throws PermErrorException, RequireClientDomainException {

        log.debug("Start do expand explanation: " + input);

        String[] parts = input.split(" ");
        StringBuffer res = new StringBuffer();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) res.append(" ");
            res.append(expandMacroString(parts[i], macroData, true));
        }
        log.debug("Done expand explanation: " + res);
        
        return res.toString();
    }

    /**
     * This method expand the given domain. So all known macros get replaced
     * 
     * @param input
     *            The domain which should be expand
     * @return expanded The domain with replaced macros
     * @throws PermErrorException
     *             This get thrown if invalid macros are used
     * @throws RequireClientDomain 
     */
    private String expandDomain(String input, MacroData macroData) throws PermErrorException, RequireClientDomainException {

        log.debug("Start expand domain: " + input);

        Matcher inputMatcher = domainSpecPattern.matcher(input);
        if (!inputMatcher.matches() || inputMatcher.groupCount() != 2) {
            throw new PermErrorException("Invalid DomainSpec: "+input);
        }

        StringBuffer res = new StringBuffer();
        if (inputMatcher.group(1) != null && inputMatcher.group(1).length() > 0) {
            res.append(expandMacroString(inputMatcher.group(1), macroData, false));
        }
        if (inputMatcher.group(2) != null && inputMatcher.group(2).length() > 0) {
            if (inputMatcher.group(2).startsWith(".")) {
                res.append(inputMatcher.group(2));
            } else {
                res.append(expandMacroString(inputMatcher.group(2), macroData, false));
            }
        }
        
        String domainName = expandMacroString(input, macroData, false);
        // reduce to less than 255 characters, deleting subdomains from left
        int split = 0;
        while (domainName.length() > 255 && split > -1) {
            split = domainName.indexOf(".");
            domainName = domainName.substring(split + 1);
        }

        log.debug("Domain expanded: " + domainName);
        
        return domainName;
    }

    /**
     * Expand the given String
     * 
     * @param input
     *            The inputString which should get expanded
     * @return expanded The expanded given String
     * @throws PermErrorException
     *             This get thrown if invalid macros are used
     * @throws RequireClientDomain 
     */
    private String expandMacroString(String input, MacroData macroData, boolean isExplanation) throws PermErrorException, RequireClientDomainException {

        StringBuffer decodedValue = new StringBuffer();
        Matcher inputMatcher = macroStringPattern.matcher(input);
        String macroCell;
        int pos = 0;

        while (inputMatcher.find()) {
            String match2 = inputMatcher.group();
            if (pos != inputMatcher.start()) {
                throw new PermErrorException("Middle part does not match: "+input.substring(0,pos)+">>"+input.substring(pos, inputMatcher.start())+"<<"+input.substring(inputMatcher.start())+" ["+input+"]");
            }
            if (match2.length() > 0) {
                if (match2.startsWith("%{")) {
                    macroCell = input.substring(inputMatcher.start() + 2, inputMatcher
                            .end() - 1);
                    inputMatcher
                            .appendReplacement(decodedValue, escapeForMatcher(replaceCell(macroCell, macroData, isExplanation)));
                } else if (match2.length() == 2 && match2.startsWith("%")) {
                    // handle the % escaping
                    /*
                     * From RFC4408:
                     * 
                     * A literal "%" is expressed by "%%".
                     *   "%_" expands to a single " " space.
                     *   "%-" expands to a URL-encoded space, viz., "%20".
                     */
                    if ("%_".equals(match2)) {
                        inputMatcher.appendReplacement(decodedValue, " ");
                    } else if ("%-".equals(match2)) {
                        inputMatcher.appendReplacement(decodedValue, "%20");
                    } else {
                        inputMatcher.appendReplacement(decodedValue, escapeForMatcher(match2.substring(1)));
                    }
                }
            }
            
            pos = inputMatcher.end();
        }
        
        if (input.length() != pos) {
            throw new PermErrorException("End part does not match: "+input.substring(pos));
        }
        
        inputMatcher.appendTail(decodedValue);

        return decodedValue.toString();
    }

    /**
     * Replace the macros in given String
     * 
     * @param replaceValue
     *            The String in which known macros should get replaced
     * @return returnData The String with replaced macros
     * @throws PermErrorException
     *             Get thrown if an error in processing happen
     * @throws RequireClientDomain 
     */
    private String replaceCell(String replaceValue, MacroData macroData, boolean isExplanation) throws PermErrorException, RequireClientDomainException {

        String variable = "";
        String domainNumber = "";
        boolean isReversed = false;
        String delimeters = ".";

        
        // Get only command character so that 'r' command and 'r' modifier don't
        // clash
        String commandCharacter = replaceValue.substring(0, 1);
        Matcher cellMatcher;
        // Find command
        if (isExplanation) {
            cellMatcher = macroLettersExpPattern.matcher(commandCharacter);
        } else {
            cellMatcher = macroLettersPattern.matcher(commandCharacter);
        }
        if (cellMatcher.find()) {
            if (cellMatcher.group().toUpperCase().equals(cellMatcher.group())) {
                variable = encodeURL(matchMacro(cellMatcher.group(), macroData));
            } else {
                variable = matchMacro(cellMatcher.group(), macroData);
            }
            // Remove Macro code so that r macro code does not clash with r the
            // reverse modifier
            replaceValue = replaceValue.substring(1);
        } else {
            throw new PermErrorException("MacroLetter not found: "+replaceValue);
        }

        // Find number of domains to use
        cellPattern = Pattern.compile("\\d+");
        cellMatcher = cellPattern.matcher(replaceValue);
        while (cellMatcher.find()) {
            domainNumber = cellMatcher.group();
            if (Integer.parseInt(domainNumber) == 0) {
                throw new PermErrorException(
                        "Digit transformer must be non-zero");
            }
        }
        // find if reversed
        cellPattern = Pattern.compile("r");
        cellMatcher = cellPattern.matcher(replaceValue);
        while (cellMatcher.find()) {
            isReversed = true;
        }

        // find delimeters
        cellPattern = Pattern.compile("[\\.\\-\\+\\,\\/\\_\\=]+");
        cellMatcher = cellPattern.matcher(replaceValue);
        while (cellMatcher.find()) {
            delimeters = cellMatcher.group();
        }

        // Reverse domains as necessary
        ArrayList<String> data = split(variable, delimeters);
        if (isReversed) {
            data = reverse(data);
        }

        // Truncate domain name to number of sub sections
        String returnData;
        if (!domainNumber.equals("")) {
            returnData = subset(data, Integer.parseInt(domainNumber));
        } else {
            returnData = subset(data);
        }

        return returnData;

    }

    /**
     * Get the value for the given macro like descripted in the RFC
     * 
     * @param macro
     *            The macro we want to get the value for
     * @return rValue The value for the given macro
     * @throws PermErrorException
     *             Get thrown if the given variable is an unknown macro
     * @throws RequireClientDomain requireClientDomain if the client domain is needed
     *             and not yet resolved.
     */
    private String matchMacro(String macro, MacroData macroData) throws PermErrorException, RequireClientDomainException {

        String rValue = null;

        String variable = macro.toLowerCase();
        if (variable.equalsIgnoreCase("i")) {
            rValue = macroData.getMacroIpAddress();
        } else if (variable.equalsIgnoreCase("s")) {
            rValue = macroData.getMailFrom();
        } else if (variable.equalsIgnoreCase("h")) {
            rValue = macroData.getHostName();
        } else if (variable.equalsIgnoreCase("l")) {
            rValue = macroData.getCurrentSenderPart();
        } else if (variable.equalsIgnoreCase("d")) {
            rValue = macroData.getCurrentDomain();
        } else if (variable.equalsIgnoreCase("v")) {
            rValue = macroData.getInAddress();
        } else if (variable.equalsIgnoreCase("t")) {
            rValue = Long.toString(macroData.getTimeStamp());
        } else if (variable.equalsIgnoreCase("c")) {
            rValue = macroData.getReadableIP();
        } else if (variable.equalsIgnoreCase("p")) {
            rValue = macroData.getClientDomain();
            if (rValue == null) {
                throw new RequireClientDomainException();
            }
        } else if (variable.equalsIgnoreCase("o")) {
            rValue = macroData.getSenderDomain();
        } else if (variable.equalsIgnoreCase("r")) {
            rValue = macroData.getReceivingDomain();
            if (rValue == null) {
                rValue = "unknown";
                List<String> dNames = dnsProbe.getLocalDomainNames();

                for (int i = 0; i < dNames.size(); i++) {
                    // check if the domainname is a FQDN
                    if (SPF1Utils.checkFQDN(dNames.get(i).toString())) {
                        rValue = dNames.get(i).toString();
                        if (macroData instanceof SPFSession) {
                            ((SPFSession) macroData).setReceivingDomain(rValue);
                        }
                        break;
                    }
                }
            }
        }

        if (rValue == null) {
            throw new PermErrorException("Unknown command : " + variable);

        } else {
            log.debug("Used macro: " + macro + " replaced with: " + rValue);

            return rValue;
        }
    }

    /**
     * Create an ArrayList by the given String. The String get splitted by given
     * delimeters and one entry in the Array will be made for each splited
     * String
     * 
     * @param data
     *            The String we want to put in the Array
     * @param delimeters
     *            The delimeter we want to use to split the String
     * @return ArrayList which contains the String parts
     */
    private ArrayList<String> split(String data, String delimeters) {

        String currentChar;
        StringBuffer element = new StringBuffer();
        ArrayList<String> splitParts = new ArrayList<String>();

        for (int i = 0; i < data.length(); i++) {
            currentChar = data.substring(i, i + 1);
            if (delimeters.indexOf(currentChar) > -1) {
                splitParts.add(element.toString());
                element.setLength(0);
            } else {
                element.append(currentChar);
            }
        }
        splitParts.add(element.toString());
        return splitParts;
    }

    /**
     * Reverse an ArrayList
     * 
     * @param data
     *            The ArrayList we want to get reversed
     * @return reversed The reversed given ArrayList
     */
    private ArrayList<String> reverse(ArrayList<String> data) {

        ArrayList<String> reversed = new ArrayList<String>();
        for (int i = 0; i < data.size(); i++) {
            reversed.add(0, data.get(i));
        }
        return reversed;
    }

    /**
     * @see #subset(ArrayList, int)
     */
    private String subset(ArrayList<String> data) {
        return subset(data, data.size());
    }

    /**
     * Convert a ArrayList to a String which holds the entries seperated by dots
     * 
     * @param data The ArrayList which should be converted
     * @param length The ArrayLength
     * @return A String which holds all entries seperated by dots
     */
    private String subset(ArrayList<String> data, int length) {

        StringBuffer buildString = new StringBuffer();
        if (data.size() < length) {
            length = data.size();
        }
        int start = data.size() - length;
        for (int i = start; i < data.size(); i++) {
            if (buildString.length() > 0) {
                buildString.append(".");
            }
            buildString.append(data.get(i));
        }
        return buildString.toString();

    }

    /**
     * Encode the given URL to UTF-8
     * 
     * @param data
     *            url to encode
     * @return encoded URL
     */
    private String encodeURL(String data) {

        try {
            // TODO URLEncoder method is not RFC2396 compatible, known
            // difference
            // is Space character gets converted to "+" rather than "%20"
            // Is there anything else which is not correct with URLEncoder?
            // Couldn't find a RFC2396 encoder
            data = URLEncoder.encode(data, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            // This shouldn't happen ignore it!
        }

        // workaround for the above descripted problem
        return data.replaceAll("\\+", "%20");

    }
    
    /**
     * Because Dollar signs may be treated as references to captured subsequences in method Matcher.appendReplacement
     * its necessary to escape Dollar signs because its allowed in the local-part of an emailaddress.
     * 
     * See JSPF-71 for the bugreport
     * 
     * @param raw
     * @return escaped string
     */
    private String escapeForMatcher(String raw) {
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if (c == '$' || c == '\\') {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.toString();
    }

}
