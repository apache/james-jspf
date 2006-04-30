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

import org.apache.spf.mechanismn.AMechanism;
import org.apache.spf.mechanismn.AllMechanism;
import org.apache.spf.mechanismn.Directive;
import org.apache.spf.mechanismn.ExistsMechanism;
import org.apache.spf.mechanismn.IP4Mechanism;
import org.apache.spf.mechanismn.IP6Mechanism;
import org.apache.spf.mechanismn.IncludeMechanism;
import org.apache.spf.mechanismn.MXMechanism;
import org.apache.spf.mechanismn.Mechanism;
import org.apache.spf.mechanismn.PTRMechanism;
import org.apache.spf.modifier.ExpModifier;
import org.apache.spf.modifier.Modifier;
import org.apache.spf.modifier.RedirectModifier;
import org.apache.spf.modifier.UnknownModifier;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class can be used ass parses for validate SPF1-Records. It also offer a
 * Collection of SPF1.Mechanism .
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 */
public class SPF1Parser {

    private Collection directives = new ArrayList();
    
    private Collection modifiers = new ArrayList();
    
    /**
     * Regex based on http://ftp.rfc-editor.org/in-notes/authors/rfc4408.txt.
     * This will be the next official SPF-Spec
     */

    // Stefano go ahead ;-)
    // TODO: check all regex!
    // TODO: fix the Quantifier problem
    // TODO: ignore case 
    static public final String ALPHA_DIGIT_PATTERN = "[a-zA-Z0-9]";

    static public final String ALPHA_PATTERN = "[a-zA-Z]";

    private static final String MACRO_LETTER_PATTERN = "[lsoditpvhcrLSODITPVHCR]";

    private static final String TRANSFORMERS_REGEX = "\\d*[r]?";

    private static final String DELEMITER_REGEX = "[\\.\\-\\+,/_\\=]";

    static public final String MACRO_EXPAND_REGEX = "\\%(?:\\{"
            + MACRO_LETTER_PATTERN + TRANSFORMERS_REGEX + DELEMITER_REGEX + "*"
            + "\\}|\\%|\\_|\\-)";

    private static final String MACRO_LITERAL_REGEX = "[\\x21-\\x24\\x26-\\x7e]"; // TODO:

    // Check
    // if
    // thats
    // really
    // right!

    /**
     * ABNF: macro-string = *( macro-expand / macro-literal )
     */
    static public final String MACRO_STRING_REGEX = "(?:" + MACRO_EXPAND_REGEX + "|"
            + MACRO_LITERAL_REGEX + "{1})*";
    /**
     * ABNF: qualifier = "+" / "-" / "?" / "~"
     */
    private static final String QUALIFIER_PATTERN = "[\\+\\-\\?\\~]";


    /**
     * ABNF: mechanism = ( all / include / A / MX / PTR / IP4 / IP6 / exists )
     */
    private static final String MECHANISM_REGEX = "(?:" + AllMechanism.ALL_REGEX  + "|" + IncludeMechanism.INCLUDE_REGEX + "|"
            + AMechanism.A_REGEX + "|" + MXMechanism.MX_REGEX + "|" + PTRMechanism.PTR_REGEX + "|" + IP4Mechanism.IP4_REGEX
            + "|" + IP6Mechanism.IP6_REGEX + "|" + ExistsMechanism.EXISTS_REGEX + ")";

    /**
     * ABNF: mechanism = ( all / include / A / MX / PTR / IP4 / IP6 / exists )
     * define mechanisms names but "all": all is different from other mechanisms because it does not
     * take parameters.
     */
    private static final String MECHANISM_NAME_STEP_REGEX = "(?:"+ AllMechanism.ALL_NAME_REGEX + "|" + IncludeMechanism.INCLUDE_NAME_REGEX +"|"+ AMechanism.A_NAME_REGEX +"|"+ MXMechanism.MX_NAME_REGEX +"|" + PTRMechanism.PTR_NAME_REGEX + "|" + IP4Mechanism.IP4_NAME_REGEX + "|" + IP6Mechanism.IP6_NAME_REGEX + "|" + ExistsMechanism.EXISTS_NAME_REGEX +")";
    
    /**
     * TODO check that MACRO_STRING_REGEX already include all the available chars in mechanism parameters
     */
    private static final String MECHANISM_VALUE_STEP_REGEX = "[^ ]+";
    
    /**
     * ABNF: name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
     */
    private static final String NAME_REGEX = ALPHA_PATTERN + "{1}"
            + "[A-Za-z0-9\\-\\_\\.]*";


    /**
     * ABNF: toplabel = ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *(
     * alphanum / "-" ) alphanum ) ; LDH rule plus additional TLD restrictions ;
     * (see [RFC3696], Section 2)
     */
    private static final String TOP_LABEL_REGEX = "(?:" + SPF1Parser.ALPHA_DIGIT_PATTERN + "*"
            + SPF1Parser.ALPHA_PATTERN + "{1}" + SPF1Parser.ALPHA_DIGIT_PATTERN + "*|(?:"
            + SPF1Parser.ALPHA_DIGIT_PATTERN + "+" + "\\-" + "(?:" + SPF1Parser.ALPHA_DIGIT_PATTERN
            + "|\\-)*" + SPF1Parser.ALPHA_DIGIT_PATTERN + "))";

    /**
     * ABNF: domain-end = ( "." toplabel [ "." ] ) / macro-expand
     */
    private static final String DOMAIN_END_REGEX = "(?:\\." + TOP_LABEL_REGEX + "\\.?"
            + "|" + SPF1Parser.MACRO_EXPAND_REGEX + ")";

    /**
     * ABNF: domain-spec = macro-string domain-end
     */
    public static final String DOMAIN_SPEC_REGEX = "(" + SPF1Parser.MACRO_STRING_REGEX
            + DOMAIN_END_REGEX + ")";

    
    /**
     * ABNF: unknown-modifier = name "=" macro-string
     */
    private static final String UNKNOWN_MODIFIER_REGEX = "("+ NAME_REGEX + ")\\=("
            + MACRO_STRING_REGEX +")";

    /**
     * ABNF: "redirect"
     */
    private static final String REDIRECT_NAME_REGEX = "[rR][eE][dD][iI][rR][eE][cC][tT]";

    /**
     * ABNF: domain-spec
     */
    private static final String REDIRECT_VALUE_REGEX = DOMAIN_SPEC_REGEX;

    /**
     * ABNF: redirect = "redirect" "=" domain-spec
     */
    private static final String REDIRECT_REGEX = REDIRECT_NAME_REGEX + "\\=" + REDIRECT_VALUE_REGEX;

    /**
     * ABNF: "exp"
     */
    private static final String EXP_NAME_REGEX = "[eE][xX][pP]";

    /**
     * ABNF: domain-spec
     */
    private static final String EXPLANATION_VALUE_REGEX = DOMAIN_SPEC_REGEX;

    /**
     * ABNF: explanation = "exp" "=" domain-spec
     */
    private static final String EXPLANATION_REGEX = EXP_NAME_REGEX + "\\=" + EXPLANATION_VALUE_REGEX;

    /**
     * ABNF: modifier = redirect / explanation / unknown-modifier
     */
    private static final String MODIFIER_REGEX = "(?:" + REDIRECT_REGEX + "|"
            + EXPLANATION_REGEX + "|" + UNKNOWN_MODIFIER_REGEX + ")";

    /**
     * ABNF: directive = [ qualifier ] mechanism
     */
    private static final String DIRECTIVE_REGEX = QUALIFIER_PATTERN + "?("
            + MECHANISM_REGEX + ")";

    /**
     * ABNF: 1*SP
     */
    private static final String TERMS_SEPARATOR_REGEX = "[ ]+";

    /**
     * ABNF: ( directive / modifier )
     */
    private static final String TERM_REGEX = "(?:" + DIRECTIVE_REGEX + "|" + MODIFIER_REGEX + ")";

    /**
     * ABNF: directive = [ qualifier ] mechanism
     * 
     * This is used for the step-by-step parser, don't change the groups!
     * 
     * 1) QUALIFIER
     * 2) ALL
     * 3) MECHANISM NAME
     * 4) MECHANISM VALUE
     * 5) MODIFIER NAME
     * 6) MODIFIER VALUE
     */
    private static final String TERM_STEP_REGEX = "(?:(" + QUALIFIER_PATTERN + "{1})?(?:("+ MECHANISM_NAME_STEP_REGEX + ")([\\:/]{1}" + MECHANISM_VALUE_STEP_REGEX + ")?)|(?:"+ UNKNOWN_MODIFIER_REGEX +"))";
    private static final int TERM_STEP_REGEX_QUALIFIER_POS = 1;
    private static final int TERM_STEP_REGEX_MECHANISM_NAME_POS = 2;
    private static final int TERM_STEP_REGEX_MECHANISM_VALUE_POS = 3;
    private static final int TERM_STEP_REGEX_MODIFIER_NAME_POS = 4;
    private static final int TERM_STEP_REGEX_MODIFIER_VALUE_POS = 5;

    /**
     * ABNF: terms = *( 1*SP ( directive / modifier ) )
     */
    private static final String TERMS_REGEX = "(?:" + TERMS_SEPARATOR_REGEX + TERM_REGEX +")*";
    
    /**
     * ABNF: record = "vspf1" terms
     */
    private static final String RECORD_REGEX = Pattern.quote(SPF1Utils.SPF_VERSION)+TERMS_REGEX;
    

    public SPF1Parser(String spfRecord) throws PermErrorException,
            NoneException {
        
        // check the version "header"
        if (!spfRecord.startsWith(SPF1Utils.SPF_VERSION+" ")) {
            throw new NoneException("No valid SPF Record: " + spfRecord);
        }

        // single step regexp matcher
        Pattern p = Pattern.compile(RECORD_REGEX);
        Matcher m = p.matcher(spfRecord);
//        if (!m.matches()) {
//            throw new PermErrorException("Not Parsable: " + spfRecord);
//        }
        
        // the previous check could be skipped once we'll finish the step-by-step parsing
        // we could simply keep it to have an "extra" input check.
        
        // extract terms
        String[] terms = Pattern.compile(TERMS_SEPARATOR_REGEX).split(spfRecord.replaceFirst(SPF1Utils.SPF_VERSION,""));
        
        Pattern termPattern = Pattern.compile(TERM_STEP_REGEX);
        
        // cycle terms
        for (int i = 0; i < terms.length; i++) if (terms[i].length()>0){
            Matcher termMatcher = termPattern.matcher(terms[i]);
            if (!termMatcher.matches()) {
                throw new PermErrorException("Term ["+terms[i]+"] is not syntactically valid: "+termPattern.pattern());
            }
            
            // DEBUG
            System.out.println("Qualifier : "+termMatcher.group(TERM_STEP_REGEX_QUALIFIER_POS));
            System.out.println("Mech Name : "+termMatcher.group(TERM_STEP_REGEX_MECHANISM_NAME_POS));
            System.out.println("Mech Value: "+termMatcher.group(TERM_STEP_REGEX_MECHANISM_VALUE_POS));
            System.out.println("Mod Name  : "+termMatcher.group(TERM_STEP_REGEX_MODIFIER_NAME_POS));
            System.out.println("Mod Value : "+termMatcher.group(TERM_STEP_REGEX_MODIFIER_VALUE_POS));
            
            // true if we matched a modifier, false if we matched a directive
            String modifierName = termMatcher.group(TERM_STEP_REGEX_MODIFIER_NAME_POS);
            if (modifierName != null) {
                String modifierValue = termMatcher.group(TERM_STEP_REGEX_MODIFIER_VALUE_POS);
                Pattern redirPattern = Pattern.compile(REDIRECT_VALUE_REGEX);
                Matcher redirMatcher = redirPattern.matcher(modifierValue);

                Pattern expPattern = Pattern.compile(EXPLANATION_VALUE_REGEX);
                Matcher expMatcher = expPattern.matcher(modifierValue);

                Modifier mod = null;
                // MODIFIER
                if (Pattern.compile(REDIRECT_NAME_REGEX).matcher(modifierName).matches()) {
                    // redirect
                    if (!redirMatcher.matches()) {
                        throw new PermErrorException("Error parsing redirect value");
                    }
                    // TODO check error for multiple modifiers 
//                  if (directives.contains(e)) {
//                      throw new PermErrorException(
//                              "More then one exp modifier found in SPF-Record");
//                  }
                    mod = new RedirectModifier();
                    ((RedirectModifier) mod).init(redirMatcher.group(1));
                } else if (Pattern.compile(EXP_NAME_REGEX).matcher(modifierName).matches()) {
                    // exp
                    if (!expMatcher.matches()) {
                        throw new PermErrorException("Error parsing redirect value");
                    }
                    // TODO check error for multiple modifiers 
//                    if (directives.contains(e)) {
//                        throw new PermErrorException(
//                                "More then one exp modifier found in SPF-Record");
//                    }
                    mod = new ExpModifier();
                    ((ExpModifier) mod).init(redirMatcher.group(1));
                } else {
                    // unknown
                    mod = new UnknownModifier();
                }
                modifiers.add(mod);
                
            } else {
                // DIRECTIVE
                String qualifier = termMatcher.group(TERM_STEP_REGEX_QUALIFIER_POS);
                String mechName = termMatcher.group(TERM_STEP_REGEX_MECHANISM_NAME_POS);
                String mechValue = termMatcher.group(TERM_STEP_REGEX_MECHANISM_VALUE_POS);
                
                Mechanism mech = null;
                if (Pattern.compile(AllMechanism.ALL_NAME_REGEX).matcher(mechName).matches()) {
                    mech = new AllMechanism();
                } else if (Pattern.compile(IncludeMechanism.INCLUDE_NAME_REGEX).matcher(mechName).matches()) {
                    mech = new IncludeMechanism();
                } else if (Pattern.compile(AMechanism.A_NAME_REGEX).matcher(mechName).matches()) {
                    mech = new AMechanism();
                } else if (Pattern.compile(MXMechanism.MX_NAME_REGEX).matcher(mechName).matches()) {
                    mech = new MXMechanism();
                } else if (Pattern.compile(IP4Mechanism.IP4_NAME_REGEX).matcher(mechName).matches()) {
                    mech = new IP4Mechanism();
                } else if (Pattern.compile(IP6Mechanism.IP6_NAME_REGEX).matcher(mechName).matches()) {
                    mech = new IP6Mechanism();
                } else if (Pattern.compile(PTRMechanism.PTR_NAME_REGEX).matcher(mechName).matches()) {
                    mech = new PTRMechanism();
                } else if (Pattern.compile(ExistsMechanism.EXISTS_NAME_REGEX).matcher(mechName).matches()) {
                    mech = new ExistsMechanism();
                }
                mech.init(mechValue);
                directives.add(new Directive(getQualifier(qualifier), mech));
            }
            
        }

        
        // further check. We should remove this if it never catches more errors
        // than the default one.
        if (!m.matches()) {
            throw new PermErrorException("Not Parsable: " + spfRecord);
        }
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
        if (mechRecord == null) {
            return SPF1Utils.PASS;
        } else if (mechRecord.startsWith(SPF1Utils.FAIL)) {
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
     * Return the commands as Collection
     * 
     * @return commands Collection of all mechanism which should be used
     */
    public Collection getDirectives() {
        return sortCommands(directives);
    }

    /**
     * Sort the commands. The redirect modifier must be the last!
     * @param commands A Collection of all commands
     * @return sortedCommands Sorted collection of the commands
     */
    private Collection sortCommands(Collection commands) {
        Collection sortedCommands = new ArrayList();
        Object redirect = null;

        Iterator c = commands.iterator();
        while (c.hasNext()) {
            Object com = c.next();

            if (com instanceof RedirectModifier) {
                redirect = com;
            } else {
                sortedCommands.add(com);
            }
        }

        if (redirect != null) {
            sortedCommands.add(redirect);
        }

        return sortedCommands;
    }

    public Collection getModifiers() {
        return modifiers;
    }
}
