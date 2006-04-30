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

import java.lang.reflect.Field;
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
    
    private static final Class[] knownMechanisms = new Class[] {
        AllMechanism.class,
        AMechanism.class,
        ExistsMechanism.class,
        IncludeMechanism.class,
        IP4Mechanism.class,
        IP6Mechanism.class,
        MXMechanism.class,
        PTRMechanism.class
    };

    private static final Class[] knownModifiers = new Class[] {
        ExpModifier.class,
        RedirectModifier.class,
        UnknownModifier.class
    };

    /**
     * Regex based on http://ftp.rfc-editor.org/in-notes/authors/rfc4408.txt.
     * This will be the next official SPF-Spec
     */

    // TODO: fix the Quantifier problem
    // What is the "Quantifier problem"?
    public static final String ALPHA_DIGIT_PATTERN = "[a-zA-Z0-9]";

    public static final String ALPHA_PATTERN = "[a-zA-Z]";

    private static final String MACRO_LETTER_PATTERN = "[lsoditpvhcrLSODITPVHCR]";

    private static final String TRANSFORMERS_REGEX = "\\d*[r]?";

    private static final String DELEMITER_REGEX = "[\\.\\-\\+,/_\\=]";

    public static final String MACRO_EXPAND_REGEX = "\\%(?:\\{"
            + MACRO_LETTER_PATTERN + TRANSFORMERS_REGEX + DELEMITER_REGEX + "*"
            + "\\}|\\%|\\_|\\-)";

    private static final String MACRO_LITERAL_REGEX = "[\\x21-\\x24\\x26-\\x7e]";

    /**
     * ABNF: macro-string = *( macro-expand / macro-literal )
     */
    public static final String MACRO_STRING_REGEX = "(?:" + MACRO_EXPAND_REGEX
            + "|" + MACRO_LITERAL_REGEX + "{1})*";

    /**
     * ABNF: qualifier = "+" / "-" / "?" / "~"
     */
    private static final String QUALIFIER_PATTERN = "[\\+\\-\\?\\~]";

    /**
     * ABNF: mechanism = ( all / include / A / MX / PTR / IP4 / IP6 / exists )
     */
    private static final String MECHANISM_REGEX = "(?:"
            + AllMechanism.REGEX + "|" 
            + IncludeMechanism.REGEX + "|" 
            + AMechanism.REGEX + "|" 
            + MXMechanism.REGEX + "|"
            + PTRMechanism.REGEX + "|" 
            + IP4Mechanism.REGEX + "|"
            + IP6Mechanism.REGEX + "|" 
            + ExistsMechanism.REGEX + ")";

    /**
     * ABNF: mechanism = ( all / include / A / MX / PTR / IP4 / IP6 / exists )
     * define mechanisms names but "all": all is different from other mechanisms
     * because it does not take parameters.
     */
    private static final String MECHANISM_NAME_STEP_REGEX = "(?:"
            + AllMechanism.NAME_REGEX + "|"
            + IncludeMechanism.NAME_REGEX + "|"
            + AMechanism.NAME_REGEX + "|" 
            + MXMechanism.NAME_REGEX + "|"
            + PTRMechanism.NAME_REGEX + "|" 
            + IP4Mechanism.NAME_REGEX + "|" 
            + IP6Mechanism.NAME_REGEX + "|"
            + ExistsMechanism.NAME_REGEX + ")";

    /**
     * TODO check that MACRO_STRING_REGEX already include all the available
     * chars in mechanism parameters
     */
    private static final String MECHANISM_VALUE_STEP_REGEX = MACRO_STRING_REGEX;

    /**
     * ABNF: toplabel = ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *(
     * alphanum / "-" ) alphanum ) ; LDH rule plus additional TLD restrictions ;
     * (see [RFC3696], Section 2)
     */
    private static final String TOP_LABEL_REGEX = "(?:"
            + SPF1Parser.ALPHA_DIGIT_PATTERN + "*" + SPF1Parser.ALPHA_PATTERN
            + "{1}" + SPF1Parser.ALPHA_DIGIT_PATTERN + "*|(?:"
            + SPF1Parser.ALPHA_DIGIT_PATTERN + "+" + "\\-" + "(?:"
            + SPF1Parser.ALPHA_DIGIT_PATTERN + "|\\-)*"
            + SPF1Parser.ALPHA_DIGIT_PATTERN + "))";

    /**
     * ABNF: domain-end = ( "." toplabel [ "." ] ) / macro-expand
     */
    private static final String DOMAIN_END_REGEX = "(?:\\." + TOP_LABEL_REGEX
            + "\\.?" + "|" + SPF1Parser.MACRO_EXPAND_REGEX + ")";

    /**
     * ABNF: domain-spec = macro-string domain-end
     */
    public static final String DOMAIN_SPEC_REGEX = "("
            + SPF1Parser.MACRO_STRING_REGEX + DOMAIN_END_REGEX + ")";

    /**
     * ABNF: modifier = redirect / explanation / unknown-modifier
     */
    private static final String MODIFIER_REGEX = "(?:" + RedirectModifier.REGEX + "|"
            + ExpModifier.REGEX + "|" + UnknownModifier.REGEX + ")";

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
    private static final String TERM_REGEX = "(?:" + DIRECTIVE_REGEX + "|"
            + MODIFIER_REGEX + ")";

    /**
     * ABNF: directive = [ qualifier ] mechanism
     * 
     * This is used for the step-by-step parser, don't change the groups!
     * 
     * 1) QUALIFIER 2) ALL 3) MECHANISM NAME 4) MECHANISM VALUE 5) MODIFIER NAME
     * 6) MODIFIER VALUE
     */
    private static final String TERM_STEP_REGEX = "(?:(" + QUALIFIER_PATTERN
            + "{1})?(?:(" + MECHANISM_NAME_STEP_REGEX + ")([\\:/]{1}"
            + MECHANISM_VALUE_STEP_REGEX + ")?)|(?:" + UnknownModifier.REGEX
            + "))";

    private static final int TERM_STEP_REGEX_QUALIFIER_POS = 1;

    private static final int TERM_STEP_REGEX_MECHANISM_NAME_POS = 2;

    private static final int TERM_STEP_REGEX_MECHANISM_VALUE_POS = 3;

    private static final int TERM_STEP_REGEX_MODIFIER_NAME_POS = 4;

    private static final int TERM_STEP_REGEX_MODIFIER_VALUE_POS = 5;

    /**
     * ABNF: terms = *( 1*SP ( directive / modifier ) )
     */
    private static final String TERMS_REGEX = "(?:" + TERMS_SEPARATOR_REGEX
            + TERM_REGEX + ")*";

    /**
     * ABNF: record = "vspf1" terms
     */
    private static final String RECORD_REGEX = Pattern
            .quote(SPF1Utils.SPF_VERSION)
            + TERMS_REGEX;

    public SPF1Parser() {
    }
    
    
    public SPF1Record parse(String spfRecord) throws PermErrorException, NoneException {
        
        SPF1Record result = new SPF1Record();

        // check the version "header"
        if (!spfRecord.startsWith(SPF1Utils.SPF_VERSION + " ")) {
            throw new NoneException("No valid SPF Record: " + spfRecord);
        }

        // single step regexp matcher
        Pattern p = Pattern.compile(RECORD_REGEX);
        Matcher m = p.matcher(spfRecord);
        // if (!m.matches()) {
        // throw new PermErrorException("Not Parsable: " + spfRecord);
        // }

        // the previous check could be skipped once we'll finish the
        // step-by-step parsing
        // we could simply keep it to have an "extra" input check.

        // extract terms
        String[] terms = Pattern.compile(TERMS_SEPARATOR_REGEX).split(
                spfRecord.replaceFirst(SPF1Utils.SPF_VERSION, ""));

        Pattern termPattern = Pattern.compile(TERM_STEP_REGEX);

        // cycle terms
        for (int i = 0; i < terms.length; i++)
            if (terms[i].length() > 0) {
                Matcher termMatcher = termPattern.matcher(terms[i]);
                if (!termMatcher.matches()) {
                    throw new PermErrorException("Term [" + terms[i]
                            + "] is not syntactically valid: "
                            + termPattern.pattern());
                }

                // DEBUG
                System.out.println("Qualifier : "
                        + termMatcher.group(TERM_STEP_REGEX_QUALIFIER_POS));
                System.out
                        .println("Mech Name : "
                                + termMatcher
                                        .group(TERM_STEP_REGEX_MECHANISM_NAME_POS));
                System.out.println("Mech Value: "
                        + termMatcher
                                .group(TERM_STEP_REGEX_MECHANISM_VALUE_POS));
                System.out.println("Mod Name  : "
                        + termMatcher.group(TERM_STEP_REGEX_MODIFIER_NAME_POS));
                System.out
                        .println("Mod Value : "
                                + termMatcher
                                        .group(TERM_STEP_REGEX_MODIFIER_VALUE_POS));

                // true if we matched a modifier, false if we matched a
                // directive
                String modifierName = termMatcher
                        .group(TERM_STEP_REGEX_MODIFIER_NAME_POS);
                if (modifierName != null) {
                    String modifierValue = termMatcher
                            .group(TERM_STEP_REGEX_MODIFIER_VALUE_POS);
                    Pattern redirPattern = Pattern
                            .compile(RedirectModifier.VALUE_REGEX);
                    Matcher redirMatcher = redirPattern.matcher(modifierValue);

                    Pattern expPattern = Pattern
                            .compile(ExpModifier.VALUE_REGEX);
                    Matcher expMatcher = expPattern.matcher(modifierValue);

                    Modifier mod = null;
                    // MODIFIER
                    if (Pattern.compile(RedirectModifier.NAME_REGEX).matcher(
                            modifierName).matches()) {
                        // redirect
                        if (!redirMatcher.matches()) {
                            throw new PermErrorException(
                                    "Error parsing redirect value");
                        }
                        mod = new RedirectModifier();
                        ((RedirectModifier) mod).init(redirMatcher.group(1));
                    } else if (Pattern.compile(ExpModifier.NAME_REGEX).matcher(
                            modifierName).matches()) {
                        // exp
                        if (!expMatcher.matches()) {
                            throw new PermErrorException(
                                    "Error parsing redirect value");
                        }
                        mod = new ExpModifier();
                        ((ExpModifier) mod).init(redirMatcher.group(1));
                    } else {
                        // unknown
                        mod = new UnknownModifier();
                    }
                    
                    if (mod.enforceSingleInstance()) {
                        Iterator it = result.getModifiers().iterator();
                        while (it.hasNext()) {
                            if (it.next().getClass().equals(mod.getClass())) {
                                throw new PermErrorException("More than one "+modifierName+" found in SPF-Record");
                            }
                        }
                    }
                    
                    result.getModifiers().add(mod);

                } else {
                    // DIRECTIVE
                    String qualifier = termMatcher
                            .group(TERM_STEP_REGEX_QUALIFIER_POS);
                    String mechName = termMatcher
                            .group(TERM_STEP_REGEX_MECHANISM_NAME_POS);
                    String mechValue = termMatcher
                            .group(TERM_STEP_REGEX_MECHANISM_VALUE_POS);

                    Mechanism mech = null;
                    for (int j = 0; j < knownMechanisms.length; j++) {
                        Class mechClass = knownMechanisms[j];
                        try {
                            Field f = mechClass.getField("NAME_REGEX");
                            String nameReg = (String) f.get(null);

                            if (Pattern.compile(nameReg).matcher(mechName).matches()) {
                                mech = (Mechanism) mechClass.newInstance();
                            }

                            
                        } catch (SecurityException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        } catch (NoSuchFieldException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        } catch (IllegalArgumentException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        } catch (IllegalAccessException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        } catch (InstantiationException e) {
                            // TODO Auto-generated catch block
                            e.printStackTrace();
                        }
                    }

                    mech.init(mechValue);
                    result.getDirectives().add(new Directive(getQualifier(qualifier), mech));
                }

            }

        // further check. We should remove this if it never catches more errors
        // than the default one.
        if (!m.matches()) {
            throw new PermErrorException("Not Parsable: " + spfRecord);
        }
        
        return result;
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
    
}
