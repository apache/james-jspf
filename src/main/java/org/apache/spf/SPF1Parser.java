/***********************************************************************
 * Copyright (c) 1999-2006 The Apache Software Foundation.             *
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

package org.apache.spf;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SPF1Parser {

    private String parsedRecord = null;

    /**
     * Regex based on http://ftp.rfc-editor.org/in-notes/authors/rfc4408.txt.
     * This will be the next official SPF-Spec
     */
    // TODO: check all regex!
    private final String ALPHA_DIGIT_PATTERN = "[a-zA-Z0-9]";

    private final String ALPHA_PATTERN = "[a-zA-Z]";

    private final String MACRO_LETTER_PATTERN = "[lsoditpvhcrLSODITPVHCR]";

    private final String TRANSFORMERS_REGEX = "\\d*[r]?";

    private final String DELEMITER_REGEX = "[\\.\\-\\+,/_\\=]";

    private final String MACRO_EXPAND_REGEX = "\\% (?:\\{" + MACRO_LETTER_PATTERN
            + TRANSFORMERS_REGEX + DELEMITER_REGEX + "*" + "\\}|\\%|\\_|\\-)";

    private final String MACRO_LITERAL_REGEX = "[\\x21-\\x24\\x26-\\x7e]"; // TODO:

    // Check
    // if
    // thats
    // really
    // right!

    
    /**
     * ABNF: macro-string     = *( macro-expand / macro-literal )
     */
    private final String MACRO_STRING_REGEX = "(?:" + MACRO_EXPAND_REGEX
            + "|" + MACRO_LITERAL_REGEX + "{1})*";

    /**
     * ABNF: toplabel = ( *alphanum ALPHA *alphanum ) /
     *                ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
     *                ; LDH rule plus additional TLD restrictions
     *                ; (see [RFC3696], Section 2)
     */
    private final String TOP_LABEL_REGEX = "(?:" + ALPHA_DIGIT_PATTERN + "*"
            + ALPHA_PATTERN + "{1}" + ALPHA_DIGIT_PATTERN +"*|(?:"+ ALPHA_DIGIT_PATTERN + "+" +"\\-" + "(?:"
            + ALPHA_DIGIT_PATTERN + "|\\-)*" + ALPHA_DIGIT_PATTERN + "))";

    /**
     * ABNF: domain-end       = ( "." toplabel [ "." ] ) / macro-expand
     */
    private final String DOMAIN_END_REGEX = "(?:\\." + TOP_LABEL_REGEX
            + "\\.?" + "|" + MACRO_EXPAND_REGEX + ")";

    /**
     * ABNF: domain-spec      = macro-string domain-end
     */
    private final String DOMAIN_SPEC_REGEX = MACRO_STRING_REGEX
            + DOMAIN_END_REGEX;

    /**
     * ABNF: qualifier        = "+" / "-" / "?" / "~"
     */
    private final String QUALIFIER_PATTERN = "[\\+\\-\\?\\~]";

    
    /**
     * ABNF: include          = "include"  ":" domain-spec
     */
    private final String INCLUDE_REGEX = "include\\:" + DOMAIN_SPEC_REGEX;

    /**
     * ABNF: exists           = "exists"   ":" domain-spec
     */
    private final String EXISTS_REGEX = "exists\\:" + DOMAIN_SPEC_REGEX;

    /**
     * ABNF: ip4-cidr-length  = "/" 1*DIGIT
     */
    private final String IP4_CIDR_LENGTH_REGEX = "/\\d+";

    /**
     * ABNF: ip6-cidr-length  = "/" 1*DIGIT
     */
    private final String IP6_CIDR_LENGTH_REGEX = "/\\d+";

    /**
     * ABNF: dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
     */
    private final String DUAL_CIDR_LENGTH_REGEX = "(?:"+IP4_CIDR_LENGTH_REGEX + ")?"
            + "(?:/" + IP6_CIDR_LENGTH_REGEX +")?";


    /**
     * TODO
     * ABNF: IP4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]
     */
    private final String IP4_REGEX = "ip4\\:[0-9.]+" + "(?:" + IP4_CIDR_LENGTH_REGEX +")?";

    /**
     * TODO
     * ABNF: IP6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]
     */
    private final String IP6_REGEX = "ip6\\:[0-9A-Fa-f\\:\\.]+" + "(?:" + IP6_CIDR_LENGTH_REGEX +")?";

    /**
     * ABNF: A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]
     */
    private final String A_REGEX = "a(?:\\:" + DOMAIN_SPEC_REGEX +")?" + "(?:"+ DUAL_CIDR_LENGTH_REGEX +")?";

    /**
     * ABNF: MX               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]
     */
    private final String MX_REGEX = "mx(?:\\:" + DOMAIN_SPEC_REGEX +")?" + "(?:"+ DUAL_CIDR_LENGTH_REGEX +")?";

    /**
     * ABNF: PTR              = "ptr"    [ ":" domain-spec ]
     */
    private final String PTR_REGEX = "ptr(?:\\:" + DOMAIN_SPEC_REGEX +")?";

    /**
     * ABNF: mechanism        = ( all / include / A / MX / PTR / IP4 / IP6 / exists )
     */
    private final String MECHANISM_REGEX = "(?:all|" + INCLUDE_REGEX + "|" + A_REGEX + "|" + MX_REGEX + "|" + PTR_REGEX + "|" + IP4_REGEX + "|" + IP6_REGEX + "|" + EXISTS_REGEX + ")";

    /**
     * ABNF: name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
     */
    private final String NAME_REGEX = ALPHA_PATTERN +"{1}" + "[A-Za-z0-9\\-\\_\\.]*";

    /**
     * ABNF: unknown-modifier = name "=" macro-string
     */
    private final String UNKNOWN_MODIFIER_REGEX = NAME_REGEX + "\\="
            + MACRO_STRING_REGEX;


    /**
     * ABNF: redirect         = "redirect" "=" domain-spec
     */
    private final String REDIRECT_REGEX = "redirect\\="+ DOMAIN_SPEC_REGEX;

    /**
     * ABNF: explanation      = "exp" "=" domain-spec
     */
    private final String EXPLANATION_REGEX = "exp\\="+ DOMAIN_SPEC_REGEX;

    /**
     * ABNF: modifier         = redirect / explanation / unknown-modifier
     */
    private final String MODIFIER_REGEX = "(?:"+ REDIRECT_REGEX + "|" + EXPLANATION_REGEX + "|"
            + UNKNOWN_MODIFIER_REGEX + ")";

    /**
     * ABNF: directive        = [ qualifier ] mechanism
     */
    private final String DIRECTIVE_REGEX = QUALIFIER_PATTERN + "?"
            + MECHANISM_REGEX;

    /**
     * ABNF: terms            = *( 1*SP ( directive / modifier ) )
     */
    private final String TERMS_REGEX = "(?:[ ]+(?:" + DIRECTIVE_REGEX + "|"
            + MODIFIER_REGEX + "))*";

    public SPF1Parser(String spfRecord, SPF1Data spfData)
            throws ErrorException, NoneException {

        //String[] recordParts = spfRecord.split(" ");

        // if the record contains no valid spfrecord we will not continue
        // and throw an NoneException
        if (!isValidSPFVersion(spfRecord)) {
            throw new NoneException("No valid SPF Record: " + spfRecord);
        } else {
            
            System.out.println(TERMS_REGEX);
            
            Pattern p = Pattern.compile(TERMS_REGEX);
            Matcher m = p.matcher(spfRecord.replaceFirst(SPF1Utils.SPF_VERSION,""));
            if (!m.matches()) {
                throw new ErrorException("Not Parsable");
            }
            
            /*
            for (int i = 0; i < recordParts.length; i++) {

                if (isAMechanism(recordParts[i])) {
                    if (!isValidAMechanismn(recordParts[i])) {
                        throw new ErrorException("No valid A Mechanism: "
                                + recordParts[i]);
                    }
                }
            }
            */
        }

    }

    /**
     * Check if the SPFRecord starts with valid version
     * 
     * @param record
     *            The Record to check
     * @return true or false
     */
    private boolean isValidSPFVersion(String record) {
        if (record.startsWith(SPF1Utils.SPF_VERSION + " ")) {
            return true;
        }
        return false;
    }

    /**
     * Method that will check if the submitted A-Mechanismn is valid
     * 
     * @param recordPart
     *            The A-Mechanismn
     * @return true or false;
     */
    private boolean isValidAMechanismn(String recordPart) {

        String record = recordPart.trim();
        if (record.startsWith("a:") || record.startsWith("A:")) {

            /**
             * Its a A Mechanismn wich has a domain-spec. The domain-spec must checked against DOMAIN_SPEC_REGEX 
             */

            String newPart = record.substring(2);
            String[] parts = newPart.split("/");

            // if there are more then 3 parts the record is not valid!
            if (parts.length < 5) {
                if (parts.length == 0) {
                    return newPart.matches(DOMAIN_SPEC_REGEX);
                } else if (parts.length == 2) {
                    return newPart.matches(DOMAIN_SPEC_REGEX
                            + IP4_CIDR_LENGTH_REGEX);
                } else if (parts.length == 4) {
                    System.out.println("HERE: " + newPart);
                    return newPart.matches(DOMAIN_SPEC_REGEX
                            + DUAL_CIDR_LENGTH_REGEX);
            } else {
                // to many parts this record cannot be valid!!
                return false;
            }
            }
        } else {
            
            /**
             * Its an A Mechanismn which has no domain-spec. 
             */
            String newPart = record.substring(1);
            String[] parts = record.split("/");

            if (parts.length < 5) {
                if (parts.length == 0) {
            return true;
                } else if (parts.length == 2) {
                    return parts[1].matches(IP4_CIDR_LENGTH_REGEX);
                } else if (parts.length == 4) {
                    return newPart.matches(DUAL_CIDR_LENGTH_REGEX);
        }
            } else {
                return true;
            }

        }
        return false;
    }

    /**
     * Check if the given part is a A Mechanismn
     * 
     * @param part
     *            The record part to check
     * @return true or false
     */
    public boolean isAMechanism(String part) {
        if ((part.startsWith("a")) || (part.startsWith("A"))) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Return the parsed record.
     * @return
     */
    public String getParsedRecord() {
        return parsedRecord;
    }
}
