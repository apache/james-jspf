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

import java.util.ArrayList;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.spf.mechanismn.AMechanism;
import org.apache.spf.mechanismn.AllMechanism;
import org.apache.spf.mechanismn.ExistsMechanism;
import org.apache.spf.mechanismn.IP4Mechanism;
import org.apache.spf.mechanismn.MXMechanism;
import org.apache.spf.mechanismn.PTRMechanism;
import org.apache.spf.modifier.ExpModifier;

/**
 * This class can be used ass parses for validate SPF1-Records. It also offer a
 * Collection of SPF1.Mechanism .
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 */
public class SPF1Parser {

    private String checkDomain = null;

    private int checkIP4 = 32;

    private int checkIP6 = 128;

    private Collection mechanism = new ArrayList();

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

    private final String MACRO_EXPAND_REGEX = "\\% (?:\\{"
            + MACRO_LETTER_PATTERN + TRANSFORMERS_REGEX + DELEMITER_REGEX + "*"
            + "\\}|\\%|\\_|\\-)";

    private final String MACRO_LITERAL_REGEX = "[\\x21-\\x24\\x26-\\x7e]"; // TODO:

    // Check
    // if
    // thats
    // really
    // right!

    /**
     * ABNF: macro-string = *( macro-expand / macro-literal )
     */
    private final String MACRO_STRING_REGEX = "(?:" + MACRO_EXPAND_REGEX + "|"
            + MACRO_LITERAL_REGEX + "{1})*";

    /**
     * ABNF: toplabel = ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *(
     * alphanum / "-" ) alphanum ) ; LDH rule plus additional TLD restrictions ;
     * (see [RFC3696], Section 2)
     */
    private final String TOP_LABEL_REGEX = "(?:" + ALPHA_DIGIT_PATTERN + "*"
            + ALPHA_PATTERN + "{1}" + ALPHA_DIGIT_PATTERN + "*|(?:"
            + ALPHA_DIGIT_PATTERN + "+" + "\\-" + "(?:" + ALPHA_DIGIT_PATTERN
            + "|\\-)*" + ALPHA_DIGIT_PATTERN + "))";

    /**
     * ABNF: domain-end = ( "." toplabel [ "." ] ) / macro-expand
     */
    private final String DOMAIN_END_REGEX = "(?:\\." + TOP_LABEL_REGEX + "\\.?"
            + "|" + MACRO_EXPAND_REGEX + ")";

    /**
     * ABNF: domain-spec = macro-string domain-end
     */
    private final String DOMAIN_SPEC_REGEX = "(" + MACRO_STRING_REGEX
            + DOMAIN_END_REGEX + ")";

    /**
     * ABNF: qualifier = "+" / "-" / "?" / "~"
     */
    private final String QUALIFIER_PATTERN = "[\\+\\-\\?\\~]";

    /**
     * ABNF: include = "include" ":" domain-spec
     */
    private final String INCLUDE_REGEX = "include\\:" + DOMAIN_SPEC_REGEX;

    /**
     * ABNF: exists = "exists" ":" domain-spec
     */
    private final String EXISTS_REGEX = "exists\\:" + DOMAIN_SPEC_REGEX;

    /**
     * ABNF: ip4-cidr-length = "/" 1*DIGIT
     */
    private final String IP4_CIDR_LENGTH_REGEX = "/(\\d+)";

    /**
     * ABNF: ip6-cidr-length = "/" 1*DIGIT
     */
    private final String IP6_CIDR_LENGTH_REGEX = "/(\\d+)";

    /**
     * ABNF: dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
     */
    private final String DUAL_CIDR_LENGTH_REGEX = "(?:" + IP4_CIDR_LENGTH_REGEX
            + ")?" + "(?:/" + IP6_CIDR_LENGTH_REGEX + ")?";

    /**
     * TODO ABNF: IP4 = "ip4" ":" ip4-network [ ip4-cidr-length ]
     */
    private final String IP4_REGEX = "ip4\\:([0-9.]+)" + "("
            + IP4_CIDR_LENGTH_REGEX + ")?";

    /**
     * TODO ABNF: IP6 = "ip6" ":" ip6-network [ ip6-cidr-length ]
     */
    private final String IP6_REGEX = "ip6\\:[0-9A-Fa-f\\:\\.]+" + "(?:"
            + IP6_CIDR_LENGTH_REGEX + ")?";

    /**
     * ABNF: A = "a" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    private final String A_REGEX = "a(?:\\:" + DOMAIN_SPEC_REGEX + ")?" + "(?:"
            + DUAL_CIDR_LENGTH_REGEX + ")?";

    /**
     * ABNF: MX = "mx" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    private final String MX_REGEX = "mx(?:\\:" + DOMAIN_SPEC_REGEX + ")?"
            + "(?:" + DUAL_CIDR_LENGTH_REGEX + ")?";

    /**
     * ABNF: PTR = "ptr" [ ":" domain-spec ]
     */
    private final String PTR_REGEX = "ptr(?:\\:" + DOMAIN_SPEC_REGEX + ")?";

    /**
     * ABNF: mechanism = ( all / include / A / MX / PTR / IP4 / IP6 / exists )
     */
    private final String MECHANISM_REGEX = "(?:all|" + INCLUDE_REGEX + "|"
            + A_REGEX + "|" + MX_REGEX + "|" + PTR_REGEX + "|" + IP4_REGEX
            + "|" + IP6_REGEX + "|" + EXISTS_REGEX + ")";

    /**
     * ABNF: name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
     */
    private final String NAME_REGEX = ALPHA_PATTERN + "{1}"
            + "[A-Za-z0-9\\-\\_\\.]*";

    /**
     * ABNF: unknown-modifier = name "=" macro-string
     */
    private final String UNKNOWN_MODIFIER_REGEX = NAME_REGEX + "\\="
            + MACRO_STRING_REGEX;

    /**
     * ABNF: redirect = "redirect" "=" domain-spec
     */
    private final String REDIRECT_REGEX = "redirect\\=" + DOMAIN_SPEC_REGEX;

    /**
     * ABNF: explanation = "exp" "=" domain-spec
     */
    private final String EXPLANATION_REGEX = "exp\\=" + DOMAIN_SPEC_REGEX;

    /**
     * ABNF: modifier = redirect / explanation / unknown-modifier
     */
    private final String MODIFIER_REGEX = "(?:" + REDIRECT_REGEX + "|"
            + EXPLANATION_REGEX + "|" + UNKNOWN_MODIFIER_REGEX + ")";

    /**
     * ABNF: directive = [ qualifier ] mechanism
     */
    private final String DIRECTIVE_REGEX = QUALIFIER_PATTERN + "?"
            + MECHANISM_REGEX;

    /**
     * ABNF: terms = *( 1*SP ( directive / modifier ) )
     */
    private final String TERMS_REGEX = "(?:[ ]+(?:" + DIRECTIVE_REGEX + "|"
            + MODIFIER_REGEX + "))*";

    private final String ALL_REGEX = "all";

    public SPF1Parser(String spfRecord) throws PermErrorException,
            NoneException {

        if (!isValidSPFVersion(spfRecord)) {
            throw new NoneException("No valid SPF Record: " + spfRecord);
        } else {
            System.out.println(TERMS_REGEX);

            String mainRecord = spfRecord.replaceFirst(SPF1Utils.SPF_VERSION,
                    "");

            Pattern p = Pattern.compile(TERMS_REGEX);
            Matcher m = p.matcher(mainRecord);
            if (!m.matches()) {
                throw new PermErrorException("Not Parsable");
            } else {
                // parse the record
                parseRecord(mainRecord);
            }
        }
    }

    /**
     * 
     * @param record
     *            The TXT or SPF Record to parse for mechanismn
     * @return mechanismn Collection of the mechanismn classes that should be
     *         used
     * @throws PermErrorException
     *             This Exception will be thrown if an PermError should be
     *             returned
     */
    private void parseRecord(String record) throws PermErrorException {

        String[] part = record.trim().split(" ");
        System.out.println("HERE!");

        Pattern ip4Pattern = Pattern.compile(IP4_REGEX);
        Pattern ip6Pattern = Pattern.compile(IP6_REGEX);
        Pattern aPattern = Pattern.compile(A_REGEX);
        Pattern mxPattern = Pattern.compile(MX_REGEX);
        Pattern ptrPattern = Pattern.compile(PTR_REGEX);
        Pattern redirPattern = Pattern.compile(REDIRECT_REGEX);
        Pattern expPattern = Pattern.compile(EXPLANATION_REGEX);
        Pattern inclPattern = Pattern.compile(INCLUDE_REGEX);
        Pattern existsPattern = Pattern.compile(EXISTS_REGEX);
        Pattern allPattern = Pattern.compile(ALL_REGEX);
        for (int i = 0; i < part.length; i++) {

            String newPart = part[i].trim();
            checkDomain = null;
            ;
            checkIP4 = 32;
            checkIP6 = 128;

            if (!newPart.equals("")) {

                // TODO: replace the System.out.println() with the
                // correct command calls

                Matcher aMatcher = aPattern.matcher(newPart);
                Matcher ip4Matcher = ip4Pattern.matcher(newPart);
                Matcher ip6Matcher = ip6Pattern.matcher(newPart);
                Matcher mxMatcher = mxPattern.matcher(newPart);
                Matcher ptrMatcher = ptrPattern.matcher(newPart);
                Matcher redirMatcher = redirPattern.matcher(newPart);
                Matcher expMatcher = expPattern.matcher(newPart);
                Matcher inclMatcher = inclPattern.matcher(newPart);
                Matcher existsMatcher = existsPattern.matcher(newPart);
                Matcher allMatcher = allPattern.matcher(newPart);

                if (aMatcher.matches()) {

                    // replace all default values with the right one
                    replaceHelper(aMatcher);

                    // create a new AMechanismn and init it
                    AMechanism a = new AMechanism();
                    a.init(getQualifier(newPart), checkDomain, checkIP4);

                    // add it to the collection
                    mechanism.add(a);

                } else if (ip4Matcher.matches()) {
                    // Replace default mask
                    replaceIP4Helper(ip4Matcher);

                    // create a new IP4Mechanismn and init it
                    IP4Mechanism ip4 = new IP4Mechanism();
                    ip4.init(getQualifier(newPart), ip4Matcher.group(1),
                            checkIP4);

                    // add it to the collection
                    mechanism.add(ip4);

                } else if (ip6Matcher.matches()) {
                    // TODO: Support ip6 Support at all
                    // replaceHelper(ip4Matcher,spfData);
                    System.out.println("IP6-Mechanismn: " + newPart);
                } else if (mxMatcher.matches()) {

                    // replace all default values with the right one
                    replaceHelper(mxMatcher);

                    // create a new MXMechanismn and init it
                    MXMechanism m = new MXMechanism();
                    m.init(getQualifier(newPart), checkDomain, checkIP4);

                    // add it to the collection
                    mechanism.add(m);

                } else if (ptrMatcher.matches()) {

                    // create a new PTRMechanismn and init it
                    PTRMechanism p = new PTRMechanism();
                    p.init(getQualifier(newPart), checkDomain, checkIP4);

                    // add it to the collection
                    mechanism.add(p);

                } else if (redirMatcher.matches()) {
                    System.out.println("Redirect:       " + newPart);
                } else if (expMatcher.matches()) {
                    // replace all default values with the right one
                    replaceHelper(expMatcher);

                    // create a new ExpMechanismn and init it
                    ExpModifier e = new ExpModifier();

                    // SPF spec says that a PermError should be thrown if more
                    // the one exp was found
                    if (mechanism.contains(e)) {
                        throw new PermErrorException(
                                "More then one exp found in SPF-Record");
                    }

                    e.init(checkDomain);

                    // add it to the collection
                    mechanism.add(e);

                } else if (inclMatcher.matches()) {
                    System.out.println("Include:        " + newPart);
                    // TODO: check what we should replace
                } else if (existsMatcher.matches()) {

                    // create a new PTRMechanismn and init it
                    ExistsMechanism e = new ExistsMechanism();
                    e.init(getQualifier(newPart), checkDomain, checkIP4);

                    // add it to the collection
                    mechanism.add(e);
                } else if (allMatcher.matches()) {

                    // create a new PTRMechanismn and init it
                    AllMechanism a = new AllMechanism();
                    a.init(getQualifier(newPart));

                    // add it to the collection
                    mechanism.add(a);

                } else {
                    throw new PermErrorException("Unknown mechanismn "
                            + newPart);
                }

            }
        }
    }

    /**
     * Method that helps to replace domain,ip4 mask, ip6 mask with the right
     * values
     * 
     * @param match
     *            The matcher for the mechanismn
     * @throws PermErrorException
     *             if an PermError should be returned
     */
    private void replaceHelper(Matcher match) throws PermErrorException {
        if (match.groupCount() > 0) {
            // replace domain
            if (match.group(1) != null) {
                checkDomain = match.group(1);

            }

            if (match.groupCount() > 1) {
                // replace ip4 mask
                if (match.group(2) != null) {
                    checkIP4 = Integer.parseInt(match.group(2).toString());
                }

                if (match.groupCount() > 2) {
                    // replace ip6 mask
                    if (match.group(3) != null) {
                        checkIP6 = Integer.parseInt(match.group(3).toString());
                    }
                }
            }
        }
    }

    /**
     * Method that helps to replace ip4 mask with the right value
     * 
     * @param match
     *            The matcher for the mechanismn
     * @throws PermErrorException
     *             if an PermError should be returned
     */
    private void replaceIP4Helper(Matcher match) throws PermErrorException {
        if (match.groupCount() > 2) {
            // replace ip4 mask
            if (match.group(3) != null) {
                checkIP4 = Integer.parseInt(match.group(3).toString());
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
     * Get the qualifier for the given mechanismn record. if none was specified
     * in the mechanismn record the qualifier for pass "+" will be used
     * 
     * @param mechRecord
     *            The mechanismn record
     * @return qualifier This qualifier will be used by the mechanismn classes
     *         for the result the return when match
     */
    private String getQualifier(String mechRecord) {

        if (mechRecord.startsWith(SPF1Utils.FAIL)) {
            return SPF1Utils.FAIL;
        } else if (mechRecord.startsWith(SPF1Utils.SOFTFAIL)) {
            return SPF1Utils.SOFTFAIL;
        } else if (mechRecord.startsWith(SPF1Utils.NEUTRAL)) {
            return SPF1Utils.NEUTRAL;
        } else {
            return SPF1Utils.PASS;
        }
    }

    /**
     * Return the mechanismn as Collection
     * 
     * @return mechanism Collection of all mechanismn which should be used
     */
    public Collection getMechanism() {
        return mechanism;
    }

}
