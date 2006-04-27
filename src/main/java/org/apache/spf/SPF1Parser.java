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

public class SPF1Parser {

    private String parsedRecord = null;

    /**
     * Regex based on http://ftp.rfc-editor.org/in-notes/authors/rfc4408.txt.
     * This will be the next official SPF-Spec
     */
    // TODO: check all regex!
    private final String ALPHA_DIGIT_REGEX = "[a-zA-Z0-9]";

    private final String MACRO_LETTER_REGEX = "[lsoditpvhcrLSODITPVHCR]";

    private final String TRANSFORMERS_REGEX = "\\d*r?";

    private final String DELEMITER_REGEX = "[\\.\\-\\+,/_\\=]";

    private final String MACRO_EXPAND_REGEX = "[(?:\\%\\{" + MACRO_LETTER_REGEX
            + TRANSFORMERS_REGEX + DELEMITER_REGEX
            + "*\\})(?:\\%\\%)(?:\\%\\_)(?:\\%\\-)]";

    private final String MACRO_LITERAL_REGEX = "[\\x21-\\x24\\x26-\\x7e]"; // TODO:

    // Check
    // if
    // thats
    // really
    // right!

    private final String MACRO_STRING_REGEX = "[(?:" + MACRO_EXPAND_REGEX
            + ")(?:" + MACRO_LITERAL_REGEX + ")]";

    private final String TOP_LABEL_REGEX = "[(?:" + ALPHA_DIGIT_REGEX + "*"
            + "[a-zA-Z]{1}\\.?)(?:" + ALPHA_DIGIT_REGEX + "+\\-" + "["
            + ALPHA_DIGIT_REGEX + "\\-]" + ALPHA_DIGIT_REGEX + ")]";

    private final String DOMAIN_END_REGEX = "[(?:\\." + TOP_LABEL_REGEX
            + "\\.*)(?:" + MACRO_EXPAND_REGEX + ")]";

    private final String DOMAIN_SPEC_REGEX = MACRO_STRING_REGEX
            + DOMAIN_END_REGEX;

    private final String QUALIFIER_REGEX = "[\\+\\-\\?\\~]";

    private final String MECHANISM_REGEX = "[(?:all)(?:include)(?:A)(?:MX)(?:PTR)(?:IP4)(?:IP6)(?:exists)]";

    private final String NAME_REGEX = "[a-zA-z][(?:a-zA-Z)(?:0-9)\\-\\_\\.]*";

    private final String UNKNOWN_MODIFIER_REGEX = NAME_REGEX + "\\-"
            + MACRO_STRING_REGEX;

    private final String MODIFIER_REGEX = "[(?:redirect)(?:explanation)(?:"
            + UNKNOWN_MODIFIER_REGEX + "]";

    private final String DIRECTIVE_REGEX = QUALIFIER_REGEX + "?"
            + MECHANISM_REGEX;

    private final String TERMS_REGEX = "(?:[ ]+[(?:" + DIRECTIVE_REGEX
            + MODIFIER_REGEX + ")])*";

    private final String IP4_CIDR_LENGTH_REGEX = "/[0-9]+";

    private final String IP6_CIDR_LENGTH_REGEX = "/[0-9]+";

    private final String DUAL_CIDR_LENTH_REGEX = IP4_CIDR_LENGTH_REGEX + "*/"
            + IP6_CIDR_LENGTH_REGEX;

    public SPF1Parser(String spfRecord, SPF1Data spfData)
            throws ErrorException, NoneException {

        String[] recordParts = spfRecord.split(" ");

        // if the record contains no valid spfrecord we will not continue
        // and throw an NoneException
        if (!isValidSPFVersion(spfRecord)) {
            throw new NoneException("No valid SPF Record: " + spfRecord);
        } else {
            for (int i = 0; i < recordParts.length; i++) {

                if (isAMechanism(recordParts[i])) {
                    if (!isValidAMechanismn(recordParts[i])) {
                        throw new ErrorException("No valid A Mechanism: "
                                + recordParts[i]);
                    }
                }
            }
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
                    return newPart.matches(DOMAIN_SPEC_REGEX
                            + IP4_CIDR_LENGTH_REGEX + IP6_CIDR_LENGTH_REGEX);
                }
            } else {
                // to many parts this record cannot be valid!!
                return false;
            }
        } else if (record.length() == 0) {
            return true;
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
