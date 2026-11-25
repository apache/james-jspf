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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.TempErrorException;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MacroExpand {
    private static final Logger LOGGER = LoggerFactory.getLogger(MacroExpand.class);

    private Pattern domainSpecPattern;

    private Pattern macroLettersPattern;

    private Pattern macroLettersExpPattern;

    private static final Pattern DIGITS_PATTERN = Pattern.compile("\\d+");

    private static final Pattern REVERSE_PATTERN = Pattern.compile("r");

    private static final Pattern DELIMITERS_PATTERN = Pattern.compile("[\\.\\-\\+\\,\\/\\_\\=]+");

    private DNSService dnsProbe;

    public static final boolean EXPLANATION = true;
    
    public static final boolean DOMAIN = false;

    /**
     * The longest expanded explanation: an SMTP reply line is at most 512 octets (RFC 5321 4.5.3.1.5). A longer
     * one is a permerror, so that the check goes on as without explanation (RFC 7208 6.2), and its expansion
     * stops there instead of growing each macro of a DNS answer of up to 64 KB into megabytes.
     */
    public static final int MAX_EXPLANATION_LENGTH = 1000;
    
    public static class RequireClientDomainException extends Exception {

        private static final long serialVersionUID = 3834282981657676530L;

    }

    /**
     * @param digits the DIGIT transformer of a macro, of any length
     * @return its value, Integer.MAX_VALUE for a larger one: more parts than there are means all of
     *         them (RFC 7208 7.1)
     */
    private static int parseDigitTransformer(String digits) {
        int zeros = 0;
        while (zeros < digits.length() && digits.charAt(zeros) == '0') {
            zeros++;
        }
        String value = digits.substring(zeros);
        if (value.length() > 9) {
            return Integer.MAX_VALUE;
        }
        return value.isEmpty() ? 0 : Integer.parseInt(value);
    }

    /**
     * The PTR names of the client address left to validate, for %{p}
     */
    private static final String ATTRIBUTE_MACRO_EXPAND_PTR_NAMES = "MacroExpand.ptrNames";

    /**
     * The PTR names of the client address validated so far, for %{p}
     */
    private static final String ATTRIBUTE_MACRO_EXPAND_VALIDATED = "MacroExpand.validated";

    /**
     * @return the PTR names of the client address validated so far
     */
    @SuppressWarnings("unchecked")
    private static List<String> validatedNames(SPFSession session) {
        return (List<String>) session.getAttribute(ATTRIBUTE_MACRO_EXPAND_VALIDATED);
    }

    /**
     * @return true when one of the addresses is the client address
     * @throws PermErrorException when the client address does not parse
     */
    private static boolean hasClientAddress(List<String> addresses, SPFSession session) throws PermErrorException {
        String client = IPAddr.getAddress(session.getIpAddress()).toString();
        for (String address : addresses) {
            try {
                if (client.equals(IPAddr.getAddress(address).toString())) {
                    return true;
                }
            } catch (PermErrorException e) {
                // no address: not the client one
            }
        }
        return false;
    }

    /**
     * @return the lookup of the addresses of the next PTR name to validate, or null when none is left: the
     *         session then holds the validated names
     */
    @SuppressWarnings("unchecked")
    private static DNSLookupContinuation validateNextPtrName(SPFSession session) {
        List<String> names = (List<String>) session.getAttribute(ATTRIBUTE_MACRO_EXPAND_PTR_NAMES);
        int type = IPAddr.isIPV6(session.getIpAddress()) ? DNSRequest.AAAA : DNSRequest.A;
        while (!names.isEmpty()) {
            String name = names.remove(0);
            try {
                DNSRequest request = new DNSRequest(name, type);
                session.setAttribute(ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD, name);
                return new DNSLookupContinuation(request, new AResponseListener());
            } catch (NoneException e) {
                // no domain name: not validated
            }
        }
        session.setValidatedClientNames(validatedNames(session));
        return null;
    }

    /**
     * Construct MacroExpand
     * 
     * @param dnsProbe the dns service to use
     */
    public MacroExpand(DNSService dnsProbe) {
        domainSpecPattern = Pattern.compile(SPFTermsRegexps.DOMAIN_SPEC_REGEX);
        // The macro letters pattern
        macroLettersExpPattern = Pattern.compile(SPFTermsRegexps.MACRO_LETTER_PATTERN_EXP);
        macroLettersPattern = Pattern.compile(SPFTermsRegexps.MACRO_LETTER_PATTERN);
        this.dnsProbe = dnsProbe;
    }
    

    /**
     * The addresses of a PTR name of the client address: the name is validated when one is the client address
     * (RFC 7208 5.5). A DNS error of the lookup skips the name.
     */
    private static final class AResponseListener implements
            SPFCheckerDNSResponseListener {
        
        /**
         * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation onDNSResponse(DNSResponse response, SPFSession session)
                throws PermErrorException, NoneException, TempErrorException,
                NeutralException {
            try {
                List<String> addresses = response.getResponse();
                if (addresses != null && hasClientAddress(addresses, session)) {
                    validatedNames(session).add((String) session.getAttribute(ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD));
                }
            } catch (TimeoutException e) {
                // RFC 7208 5.5: "that domain name is skipped and the search continues"
            } catch (PermErrorException e) {
                // a client address that does not parse: no validated name, "unknown"
                session.setValidatedClientNames(new ArrayList<>());
                return null;
            }
            return validateNextPtrName(session);
        }
    }

    /**
     * The PTR names of the client address: the first ones, up to the record limit of the DNS service (RFC 7208
     * 4.6.4), are validated in turn, once for the session, which chooses %{p} among the validated ones for each
     * domain (RFC 7208 7.3). A DNS error of the lookup makes %{p} "unknown".
     */
    private static final class PTRResponseListener implements
            SPFCheckerDNSResponseListener {

        private final int recordLimit;

        /**
         * @param recordLimit the number of names validated at most, 0 for all of them
         */
        private PTRResponseListener(int recordLimit) {
            this.recordLimit = recordLimit;
        }

        /**
         * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation onDNSResponse(DNSResponse response, SPFSession session)
                throws PermErrorException, NoneException, TempErrorException,
                NeutralException {

            try {
                List<String> names = response.getResponse();

                if (names != null && names.size() > 0) {
                    int validated = recordLimit > 0 ? Math.min(recordLimit, names.size()) : names.size();
                    session.setAttribute(ATTRIBUTE_MACRO_EXPAND_PTR_NAMES, new ArrayList<>(names.subList(0, validated)));
                    session.setAttribute(ATTRIBUTE_MACRO_EXPAND_VALIDATED, new ArrayList<String>());
                    return validateNextPtrName(session);
                }
            } catch (TimeoutException e) {
                // just return the default "unknown".
            }
                    
            session.setValidatedClientNames(new ArrayList<>());
            return null;

        }
    }

    private static final String ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD = "MacroExpand.checkedRecord";

    /**
     * Expand the input, or look up first the PTR names of the client address that %{p} needs. That lookup counts
     * against the limit of DNS-querying terms, except for an explanation.
     *
     * @see #checkExpand(String, SPFSession, boolean, boolean)
     */
    public DNSLookupContinuation checkExpand(String input, SPFSession session, boolean isExplanation) throws PermErrorException, NoneException {
        return checkExpand(input, session, isExplanation, !isExplanation);
    }

    /**
     * Expand the input, or look up first the PTR names of the client address that %{p} needs.
     *
     * @param input the domain-spec or explanation to expand
     * @param session the session
     * @param isExplanation true for an explanation
     * @param countsLookup true when the PTR lookup counts against the limit of 10 DNS-querying terms (RFC 7208
     *        4.6.4): for the terms that query DNS, not for exp=, looked up after the check
     * @return the PTR lookup, or null when the input is expanded
     * @throws PermErrorException also when that PTR lookup goes past the limit
     */
    public DNSLookupContinuation checkExpand(String input, SPFSession session, boolean isExplanation, boolean countsLookup) throws PermErrorException, NoneException {
        if (input != null) {
            String host = this.expand(input, session, isExplanation);
            if (host == null) {
                if (countsLookup) {
                    // RFC 7208 4.6.4: "the number of "PTR" resource records queried is included in the overall limit"
                    session.increaseCurrentDepth();
                }
                return new DNSLookupContinuation(new DNSRequest(IPAddr
                        .getAddress(session.getIpAddress()).getReverseIP(),
                        DNSRequest.PTR), new PTRResponseListener(dnsProbe != null ? dnsProbe.getRecordLimit() : 0));
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

        LOGGER.debug("Start do expand explanation: {}", input);

        String[] parts = input.split(" ");
        StringBuilder res = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) res.append(" ");
            res.append(expandMacroString(parts[i], macroData, true));
            checkExplanationLength(res.length());
        }
        LOGGER.debug("Done expand explanation: {}", res);
        
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

        LOGGER.debug("Start expand domain: {}", input);

        if (!domainSpecPattern.matcher(input).matches()) {
            throw new PermErrorException("Invalid DomainSpec: "+input);
        }

        String domainName = expandMacroString(input, macroData, false);
        if (domainName.indexOf('\r') >= 0 || domainName.indexOf('\n') >= 0) {
            throw new PermErrorException("Macro-expanded domain contains illegal CR or LF characters");
        }
        // reduce to 253 characters at most, not counting a trailing dot, deleting subdomains from left
        // (RFC 7208 7.3): at once, after the first dot that leaves at most that many, or else after the last dot
        int maxLength = domainName.endsWith(".") ? 254 : 253;
        if (domainName.length() > maxLength) {
            int split = domainName.indexOf('.', domainName.length() - maxLength - 1);
            if (split < 0) {
                split = domainName.lastIndexOf('.');
            }
            domainName = domainName.substring(split + 1);
        }

        LOGGER.debug("Domain expanded: {}", domainName);
        
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

        // ABNF: macro-string = *( macro-expand / macro-literal ), walked by hand: a regex find per
        // macro-literal cost a Matcher.find and a String per character of every target
        StringBuilder decodedValue = null;
        int pos = 0;
        while (pos < input.length()) {
            int macro = input.indexOf('%', pos);
            int literalsEnd = macro < 0 ? input.length() : macro;
            checkMacroLiterals(input, pos, literalsEnd);
            if (macro < 0) {
                if (decodedValue == null) {
                    // no macro-expand: the input is its own expansion
                    return input;
                }
                decodedValue.append(input, pos, literalsEnd);
                break;
            }
            if (decodedValue == null) {
                decodedValue = new StringBuilder(input.length() + 32);
            }
            decodedValue.append(input, pos, literalsEnd);
            pos = expandMacro(input, macro, decodedValue, macroData, isExplanation);
            if (isExplanation) {
                checkExplanationLength(decodedValue.length());
            }
        }

        return decodedValue == null ? input : decodedValue.toString();
    }

    private static void checkExplanationLength(int length) throws PermErrorException {
        if (length > MAX_EXPLANATION_LENGTH) {
            throw new PermErrorException("Expanded explanation longer than " + MAX_EXPLANATION_LENGTH + " characters");
        }
    }

    /**
     * ABNF: macro-literal = %x21-24 / %x26-7E
     *
     * @throws PermErrorException when a character of input, from start to end, is not a macro-literal
     */
    private static void checkMacroLiterals(String input, int start, int end) throws PermErrorException {
        for (int i = start; i < end; i++) {
            char c = input.charAt(i);
            if (c < 0x21 || c > 0x7e || c == '%') {
                throw new PermErrorException("Invalid macro-literal at " + i + ": " + input);
            }
        }
    }

    /**
     * ABNF: macro-expand = ( "%{" macro-letter transformers *delimiter "}" ) / "%%" / "%_" / "%-"
     *
     * The macro-letters of an explanation are accepted here for a domain too: replaceCell rejects
     * the ones a domain may not use.
     *
     * @param input the macro-string
     * @param start the position of the "%" of the macro-expand
     * @param out where the expansion is appended
     * @return the position after the macro-expand
     * @throws PermErrorException when there is no valid macro-expand at start
     */
    private int expandMacro(String input, int start, StringBuilder out, MacroData macroData, boolean isExplanation) throws PermErrorException, RequireClientDomainException {
        if (start + 1 >= input.length()) {
            throw new PermErrorException("Invalid macro-expand at " + start + ": " + input);
        }
        switch (input.charAt(start + 1)) {
            /*
             * From RFC4408:
             *
             * A literal "%" is expressed by "%%".
             *   "%_" expands to a single " " space.
             *   "%-" expands to a URL-encoded space, viz., "%20".
             */
            case '%':
                out.append('%');
                return start + 2;
            case '_':
                out.append(' ');
                return start + 2;
            case '-':
                out.append("%20");
                return start + 2;
            case '{':
                int end = macroCellEnd(input, start + 2);
                if (end < 0) {
                    throw new PermErrorException("Invalid macro-expand at " + start + ": " + input);
                }
                out.append(replaceCell(input.substring(start + 2, end), macroData, isExplanation));
                return end + 1;
            default:
                throw new PermErrorException("Invalid macro-expand at " + start + ": " + input);
        }
    }

    /**
     * ABNF: macro-letter transformers *delimiter "}", with transformers = *DIGIT [ "r" ]
     *
     * @return the position of the closing "}", or -1 when there is no such macro cell at start
     */
    private static int macroCellEnd(String input, int start) {
        int i = start;
        if (i >= input.length() || "rctlsodipvhRCTLSODIPVH".indexOf(input.charAt(i)) < 0) {
            return -1;
        }
        i++;
        while (i < input.length() && input.charAt(i) >= '0' && input.charAt(i) <= '9') {
            i++;
        }
        if (i < input.length() && input.charAt(i) == 'r') {
            i++;
        }
        while (i < input.length() && ".-+,/_=".indexOf(input.charAt(i)) >= 0) {
            i++;
        }
        if (i < input.length() && input.charAt(i) == '}') {
            return i;
        }
        return -1;
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
        cellMatcher = DIGITS_PATTERN.matcher(replaceValue);
        while (cellMatcher.find()) {
            domainNumber = cellMatcher.group();
            if (parseDigitTransformer(domainNumber) == 0) {
                throw new PermErrorException(
                        "Digit transformer must be non-zero");
            }
        }
        // find if reversed
        cellMatcher = REVERSE_PATTERN.matcher(replaceValue);
        while (cellMatcher.find()) {
            isReversed = true;
        }

        // find delimeters
        cellMatcher = DELIMITERS_PATTERN.matcher(replaceValue);
        while (cellMatcher.find()) {
            delimeters = cellMatcher.group();
        }

        // Reverse domains as necessary
        ArrayList<String> data = split(variable, delimeters);
        if (isReversed) {
            Collections.reverse(data);
        }

        // Truncate domain name to number of sub sections
        String returnData;
        if (!domainNumber.equals("")) {
            returnData = subset(data, parseDigitTransformer(domainNumber));
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
            LOGGER.debug("Used macro: {} replaced with: {}", macro, rValue);

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
    static ArrayList<String> split(String data, String delimeters) {

        ArrayList<String> splitParts = new ArrayList<String>();
        int start = 0;
        for (int i = 0; i < data.length(); i++) {
            if (delimeters.indexOf(data.charAt(i)) >= 0) {
                // the empty parts between two delimiters, or at an end, are kept (RFC 7208 7.3)
                splitParts.add(data.substring(start, i));
                start = i + 1;
            }
        }
        splitParts.add(data.substring(start));
        return splitParts;
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

        StringBuilder buildString = new StringBuilder();
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

}
