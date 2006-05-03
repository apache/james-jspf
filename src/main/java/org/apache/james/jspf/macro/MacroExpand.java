/***********************************************************************
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

package org.apache.james.jspf.macro;

/**
 * This Class is used to convert all macros which can used in SPF-Records to the right values!
 * 
 * @author Mimecast Contact : spf@mimecast.net
 * @author Norman Maurer <nm@byteaction.de>
 */

import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.log4j.Logger;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MacroExpand {


    public static final String MACRO_REGEX = "\\%\\{[lsoditpvhcrLSODITPVHCR]\\d*r?[\\.\\-\\+,/_\\=]*\\}";

    private MacroData spfData;

    private Pattern inputPattern;

    private Matcher inputMatcher;

    private Pattern cellPattern;

    private Matcher cellMatcher;

    private boolean isExplanation = false;
    
    
    private static Logger log = Logger.getLogger(MacroExpand.class);

    public MacroExpand(MacroData spfData) {
        this.spfData = spfData;
        inputPattern = Pattern.compile(MACRO_REGEX);
    }

    /**
     * This method expand the given a explanation
     * 
     * @param input The explanation which should be expanded
     * @return expanded The expanded explanation
     * @throws PermErrorException Get thrown if invalid macros are used
     */
    public String expandExplanation(String input) throws PermErrorException {
        
        log.debug("Start do expand explanation: " + input);
        
        isExplanation = true;
        return expand(input);
    }

    /**
     * This method expand the given domain. So all known macros get replaced
     * 
     * @param input
     *            The domain which should be expand
     * @return expanded The domain with replaced macros
     * @throws PermErrorException This get thrown if invalid macros are used
     */
    public String expandDomain(String input) throws PermErrorException {

        log.debug("Start expand domain: " + input);
        
        isExplanation = false;
        String domainName = expand(input);
        // reduce to less than 255 characters, deleting subdomains from left
        int split = 0;
        while (domainName.length() > 255 && split > -1) {
            split = domainName.indexOf(".");
            domainName = domainName.substring(split + 1);
        }
        return domainName;
    }

    /**
     * Expand the given String
     * 
     * @param input The inputString which should get expanded
     * @return expanded The expanded given String
     * @throws PermErrorException This get thrown if invalid macros are used
     */
    private String expand(String input) throws PermErrorException {

        input = replaceLiterals(input);

        StringBuffer decodedValue = new StringBuffer();
        inputMatcher = inputPattern.matcher(input);
        String macroCell;

        while (inputMatcher.find()) {
            macroCell = input.substring(inputMatcher.start() + 2, inputMatcher
                    .end() - 1);
            inputMatcher
                    .appendReplacement(decodedValue, replaceCell(macroCell));
        }
        inputMatcher.appendTail(decodedValue);

        return decodedValue.toString();
    }

    /**
     * Replace the macros in given String
     * 
     * @param replaceValue The String in which known macros should get replaced
     * @return returnData The String with replaced macros
     * @throws PermErrorException Get thrown if  an error in processing happen 
     */
    private String replaceCell(String replaceValue) throws PermErrorException {

        String variable = "";
        String domainNumber = "";
        boolean isReversed = false;
        String delimeters = ".";

        if (isExplanation) {
            // Find command
            cellPattern = Pattern.compile("[ctCT]");
            cellMatcher = cellPattern.matcher(replaceValue);
            while (cellMatcher.find()) {
                if (cellMatcher.group().toUpperCase().equals(
                        cellMatcher.group())) {
                    variable = encodeURL(matchMacro(cellMatcher.group()));
                } else {
                    variable = matchMacro(cellMatcher.group());
                }
            }
        }
        // Get only command character so that 'r' command and 'r' modifier don't
        // clash
        String commandCharacter = replaceValue.substring(0, 1);
        // Find command
        cellPattern = Pattern.compile("[lsodipvhrLSODIPVHR]");
        cellMatcher = cellPattern.matcher(commandCharacter);
        while (cellMatcher.find()) {
            if (cellMatcher.group().toUpperCase().equals(cellMatcher.group())) {
                variable = encodeURL(matchMacro(cellMatcher.group()));
            } else {
                variable = matchMacro(cellMatcher.group());
            }
        }
        // Remove Macro code so that r macro code does not clash with r the
        // reverse modifier
        replaceValue = replaceValue.substring(1);

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
        ArrayList data = split(variable, delimeters);
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
     * @param macro The macro we want to get the value for
     * @return rValue The value for the given macro
     * @throws PermErrorException Get thrown if the given variable is an unknown macro
     * 
     */
    private String matchMacro(String macro) throws PermErrorException {
        
        String rValue = null;
        
        String variable = macro.toLowerCase();
        if (variable.equalsIgnoreCase("i")) {
            rValue = spfData.getIpAddress();
        } else if (variable.equalsIgnoreCase("s")) {
            rValue = spfData.getMailFrom();
        } else if (variable.equalsIgnoreCase("h")) {
            rValue = spfData.getHostName();
        } else if (variable.equalsIgnoreCase("l")) {
            rValue = spfData.getCurrentSenderPart();
        } else if (variable.equalsIgnoreCase("d")) {
            rValue = spfData.getCurrentDomain();
        } else if (variable.equalsIgnoreCase("v")) {
            rValue = spfData.getInAddress();
        } else if (variable.equalsIgnoreCase("t")) {
            rValue = Long.toString(spfData.getTimeStamp());
        } else if (variable.equalsIgnoreCase("c")) {
            rValue = spfData.getReadableIP();
        } else if (variable.equalsIgnoreCase("p")) {
            rValue = spfData.getClientDomain();
        } else if (variable.equalsIgnoreCase("o")) {
            rValue = spfData.getSenderDomain();
        } else if (variable.equalsIgnoreCase("r")) {
            rValue = spfData.getReceivingDomain();
        }
        
        if (rValue == null) {
            throw new PermErrorException("Unknown command : " + variable);
    
        } else {
            
            log.debug("Used macro: " + macro + " replaced with: " + rValue);
            
            return  rValue;
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
    private ArrayList split(String data, String delimeters) {

        String currentChar;
        StringBuffer element = new StringBuffer();
        ArrayList splitParts = new ArrayList();

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
     * @param data The ArrayList we want to get reversed
     * @return reversed The reversed given ArrayList
     */
    private ArrayList reverse(ArrayList data) {

        ArrayList reversed = new ArrayList();
        for (int i = 0; i < data.size(); i++) {
            reversed.add(0, data.get(i));
        }
        return reversed;
    }

    private String subset(ArrayList data) {
        return subset(data, data.size());
    }

    private String subset(ArrayList data, int length) {

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
     * Replace all literals in the given String
     * 
     * @param data
     *            The String we want to replace the literals
     * @return given The given String with all literales replaced
     */
    private String replaceLiterals(String data) {

        log.debug("Replace literals on String: " + data);
        
        data = data.replaceAll("%%", "%");
        data = data.replaceAll("%_", " ");
        data = data.replaceAll("%-", "%20");
        
        log.debug("Replaced String: " + data);
        
        return data;
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