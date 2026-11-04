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


package org.apache.james.jspf.executor;

import org.apache.james.jspf.core.SPF1Utils;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;


/**
 * This class is used to return the result of an SPF lookup.
 * 
 */
public class SPFResult  {

    /**
     * The atext characters of RFC 5322 3.2.3 other than letters and digits
     */
    private static final String ATEXT_SYMBOLS = "!#$%&'*+-/=?^_`{|}~";

    /**
     * @return true for a visible character: printable ASCII, or a non-ASCII one, as UTF-8 headers
     *         hold (RFC 6532 3.2), but no control character (C0, DEL, C1)
     */
    private static boolean isVisible(int c) {
        return (c > ' ' && c < 0x7F) || c >= 0xA0;
    }

    /**
     * @return true for an atext character of RFC 5322 3.2.3, or a non-ASCII one (RFC 6532 3.2) other
     *         than a control character
     */
    private static boolean isAtext(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || ATEXT_SYMBOLS.indexOf(c) >= 0 || c >= 0xA0;
    }

    /**
     * @return true for an RFC 5322 dot-atom-text: runs of atext separated by single dots, so neither
     *         empty nor starting or ending with a dot
     */
    private static boolean isDotAtom(String value) {
        boolean afterAtext = false;
        for (char c : value.toCharArray()) {
            if (c == '.' && afterAtext) {
                afterAtext = false;
            } else if (isAtext(c)) {
                afterAtext = true;
            } else {
                return false;
            }
        }
        return afterAtext;
    }

    /**
     * Write the value of a key-value pair of the header, a dot-atom or a quoted-string (RFC 7208 9.1):
     * as it is when it is a dot-atom, else as an RFC 5322 quoted-string, of which "\\" and "\"" become
     * quoted-pairs and characters that are neither visible nor white space are dropped. A mailbox ("@",
     * quoted in the examples of RFC 7208 9.1), an IPv6 address (":"), an address literal ("[") or a
     * domain ending with a dot is quoted.
     *
     * @param value The value, given by the SMTP client
     */
    private static String keyValue(String value) {
        if (isDotAtom(value)) {
            return value;
        }
        StringBuilder quoted = new StringBuilder(value.length() + 2).append('"');
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') {
                quoted.append('\\').append(c);
            } else if (isVisible(c) || c == ' ' || c == '\t') {
                quoted.append(c);
            }
        }
        return quoted.append('"').toString();
    }

    protected String headerTextAsString = "";

    protected final static String HEADER_NAME = "Received-SPF";
    
    protected String result = null;

    protected String explanation = null;
    
    protected SPFResult() {
        
    }
    
    /**
     * Construct SPFResult
     * 
     * @param spfSession the SPFSession
     */
    public SPFResult(SPFSession spfSession) {
        setSPFSession(spfSession);
    }
    
    /**
     * Initialize the result.
     * 
     * @param spfSession
     */
    protected void setSPFSession(SPFSession spfSession) {
        this.explanation = spfSession.getExplanation();
        this.result = spfSession.getCurrentResultExpanded();
        this.headerTextAsString = generateHeader(result, spfSession);
    }

    /**
     * Get the full SPF-Header (headername and headertext)
     * 
     * @return SPF-Header
     */
    public String getHeader() {
        return HEADER_NAME+": "+getHeaderText();
    }

    /**
     * Get the SPF-Headername
     * 
     * @return headername
     */
    public String getHeaderName() {
        return HEADER_NAME;
    }

    /**
     * Get SPF-Headertext
     * 
     * @return headertext
     */
    public String getHeaderText() {
        return headerTextAsString != null ? headerTextAsString : "";
    }

    /**
     * Generate a SPF-Result header
     * 
     * @param result The result we should use to generate the header
     */
    private String generateHeader(String result, SPFSession spfData) {

        StringBuffer headerText = new StringBuffer();

        if (result.equals(SPFErrorConstants.PASS_CONV)) {
            headerText.append(result + " (spfCheck: domain of "
                    + escapeComment(spfData.getCurrentDomain()) + " designates "
                    + spfData.getIpAddress() + " as permitted sender) ");
        } else if (result.equals(SPFErrorConstants.FAIL_CONV)) {
            headerText.append(result + " (spfCheck: domain of "
                    + escapeComment(spfData.getCurrentDomain()) + " does not designate "
                    + spfData.getIpAddress() + " as permitted sender) ");
        } else if (result.equals(SPFErrorConstants.NEUTRAL_CONV)
                || result.equals(SPFErrorConstants.NONE_CONV)) {
            headerText.append(result + " (spfCheck: " + spfData.getIpAddress()
                    + " is neither permitted nor denied by domain of "
                    + escapeComment(spfData.getCurrentDomain()) + ") ");

        } else if (result.equals(SPFErrorConstants.SOFTFAIL_CONV)) {
            headerText.append(result + " (spfCheck: transitioning domain of "
                    + escapeComment(spfData.getCurrentDomain()) + " does not designate "
                    + spfData.getIpAddress() + " as permitted sender) ");
        } else if (result.equals(SPFErrorConstants.PERM_ERROR_CONV)) {
            headerText.append(result
                    + " (spfCheck: Error in processing SPF Record) ");

        } else if (result.equals(SPFErrorConstants.TEMP_ERROR_CONV)) {
            headerText.append(result
                    + " (spfCheck: Error in retrieving data from DNS) ");

        }

        String headerTextAsString;
        if (headerText.length() > 0) {
            headerText.append("client-ip=" + keyValue(spfData.getIpAddress())
                    + "; envelope-from=" + keyValue(spfData.getMailFrom()) + "; helo="
                    + keyValue(spfData.getHostName()) + ";");
            headerTextAsString = headerText.toString();
        } else {
            headerTextAsString = "";
        }
        return headerTextAsString;
    }

    /**
     * Escape a value written inside the comment of the header: "(", ")" and
     * "\\" become RFC 5322 quoted-pairs, and characters that are neither
     * ctext nor space are dropped, so that the value cannot close the comment.
     *
     * @param value The value to escape, possibly taken from DNS
     */
    private static String escapeComment(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder escaped = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (c == '(' || c == ')' || c == '\\') {
                escaped.append('\\').append(c);
            } else if (c >= ' ' && c <= '~') {
                escaped.append(c);
            }
        }
        return escaped.toString();
    }

    /**
     * Get the result string
     * 
     * @see SPF1Utils
     * @return result
     */
    public String getResult() {
        return result;
    }

    /**
     * Get the explanation string
     * If no explanation exists return the empty string
     * 
     * @return explanation
     */
    public String getExplanation() {
        return explanation != null ? explanation : "";
    }
    
    
}
