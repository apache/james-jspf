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


package org.apache.james.jspf.parser;

import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.executor.FutureSPFResult;
import org.apache.james.jspf.terms.Configuration;
import org.apache.james.jspf.terms.Directive;
import org.apache.james.jspf.terms.Mechanism;
import org.apache.james.jspf.terms.Modifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class is used to parse SPF1-Records from their textual form to an
 * SPF1Record object that is composed by 2 collections: directives and
 * modifiers.
 * 
 * The parsing is modular and get informations from Mechanism and Modifiers
 * classes declared in the org/apache/james/jspf/parser/jspf.default.terms file.
 * 
 * Each term implementation provide its own REGEX in the REGEX static public
 * field. This parser simply join all the regexp in a single "alternative"
 * pattern and count the number of catch groups (brackets) assigned to each
 * regex fragment.
 * 
 * SO it creates a big regex and an array where it store what term is associated
 * to each catch group of the big regex.
 * 
 * If the regex matches the input vspf1 record then it start looking for the
 * matched group (not null) and lookup the term that created that part of the
 * regex.
 * 
 * With this informations it creates a new instance of the term and, if the term
 * is ConfigurationEnabled it calls the config() method passing to it only the specific
 * subset of the MatchResult (using the MatchResultSubset).
 * 
 * TODO doubts about the specification - redirect or exp with no domain-spec are
 * evaluated as an unknown-modifiers according to the current spec (it does not
 * make too much sense) - top-label is defined differently in various specs.
 * We'll have to review the code. -
 * http://data.iana.org/TLD/tlds-alpha-by-domain.txt (we should probably beeter
 * use and alpha sequence being at least 2 chars - Somewhere is defined as "."
 * TLD [ "." ] - Otherwise defined as ( *alphanum ALPHA *alphanum ) / (
 * 1*alphanum "-" *( * alphanum / "-" ) alphanum )
 * 
 * @see org.apache.james.jspf.core.SPF1Record
 * 
 */
public class RFC4408SPF1Parser implements SPFRecordParser {
    private static final Logger LOGGER = LoggerFactory.getLogger(RFC4408SPF1Parser.class);

    /**
     * Regex based on http://www.ietf.org/rfc/rfc4408.txt.
     * This will be the next official SPF-Spec
     */

    // Changed this because C, T and R MACRO_LETTERS are not available 
    // in record parsing and must return a PermError.
   
    // private static final String MACRO_LETTER_PATTERN = "[lsodipvhcrtLSODIPVHCRT]";

    /**
     * ABNF: qualifier = "+" / "-" / "?" / "~"
     */
    private static final String QUALIFIER_PATTERN = "[" + "\\"
            + SPF1Constants.PASS + "\\" + SPF1Constants.FAIL + "\\"
            + SPF1Constants.NEUTRAL + "\\" + SPF1Constants.SOFTFAIL + "]";

    private Pattern termsSeparatorPattern = null;

    private Pattern termPattern = null;

    private int TERM_STEP_REGEX_QUALIFIER_POS;

    private int TERM_STEP_REGEX_MECHANISM_POS;

    private int TERM_STEP_REGEX_MODIFIER_POS;

    private List<TermDefinition> matchResultPositions;

    private TermsFactory termsFactory;

    /**
     * Constructor. Creates all the values needed to run the parsing
     * 
     * @param termsFactory the TermsFactory implementation
     */
    public RFC4408SPF1Parser(TermsFactory termsFactory) {
        this.termsFactory = termsFactory;
        
        /**
         * ABNF: mechanism = ( all / include / A / MX / PTR / IP4 / IP6 / exists )
         */
        String MECHANISM_REGEX = createRegex(termsFactory.getMechanismsCollection());

        /**
         * ABNF: modifier = redirect / explanation / unknown-modifier
         */
        String MODIFIER_REGEX = "(" + createRegex(termsFactory.getModifiersCollection()) + ")";

        /**
         * ABNF: directive = [ qualifier ] mechanism
         */
        String DIRECTIVE_REGEX = "(" + QUALIFIER_PATTERN + "?)("
                + MECHANISM_REGEX + ")";

        /**
         * ABNF: ( directive / modifier )
         */
        String TERM_REGEX = "(?:" + MODIFIER_REGEX + "|" + DIRECTIVE_REGEX
                + ")";

        /**
         * ABNF: 1*SP
         */
        String TERMS_SEPARATOR_REGEX = "[ ]+";

        termsSeparatorPattern = Pattern.compile(TERMS_SEPARATOR_REGEX);
        termPattern = Pattern.compile(TERM_REGEX);

        initializePositions();
    }

    /**
     * Fill in the matchResultPositions ArrayList. This array simply map each
     * regex matchgroup to the Term class that originated that part of the
     * regex.
     */
    private void initializePositions() {
        ArrayList<TermDefinition> matchResultPositions = new ArrayList<TermDefinition>();

        // FULL MATCH
        int posIndex = 0;
        matchResultPositions.ensureCapacity(posIndex + 1);
        matchResultPositions.add(posIndex, null);

        Iterator<TermDefinition> i;

        TERM_STEP_REGEX_MODIFIER_POS = ++posIndex;
        matchResultPositions.ensureCapacity(posIndex + 1);
        matchResultPositions.add(TERM_STEP_REGEX_MODIFIER_POS, null);
        i = termsFactory.getModifiersCollection().iterator();
        while (i.hasNext()) {
            TermDefinition td = i.next();
            int size = td.getMatchSize() + 1;
            for (int k = 0; k < size; k++) {
                posIndex++;
                matchResultPositions.ensureCapacity(posIndex + 1);
                matchResultPositions.add(posIndex, td);
            }
        }

        TERM_STEP_REGEX_QUALIFIER_POS = ++posIndex;
        matchResultPositions.ensureCapacity(posIndex + 1);
        matchResultPositions.add(posIndex, null);

        TERM_STEP_REGEX_MECHANISM_POS = ++posIndex;
        matchResultPositions.ensureCapacity(posIndex + 1);
        matchResultPositions.add(TERM_STEP_REGEX_MECHANISM_POS, null);
        i = termsFactory.getMechanismsCollection().iterator();
        while (i.hasNext()) {
            TermDefinition td = i.next();
            int size = td.getMatchSize() + 1;
            for (int k = 0; k < size; k++) {
                posIndex++;
                matchResultPositions.ensureCapacity(posIndex + 1);
                matchResultPositions.add(posIndex, td);
            }
        }

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Parsing catch group positions: Modifiers["
                    + TERM_STEP_REGEX_MODIFIER_POS + "] Qualifier["
                    + TERM_STEP_REGEX_QUALIFIER_POS + "] Mechanism["
                    + TERM_STEP_REGEX_MECHANISM_POS + "]");
            for (int k = 0; k < matchResultPositions.size(); k++) {
                LOGGER
                        .debug(k
                                + ") "
                                + (matchResultPositions.get(k) != null ? ((TermDefinition) matchResultPositions
                                        .get(k)).getPattern().pattern()
                                        : null));
            }
        }
        
        this.matchResultPositions = Collections.synchronizedList(matchResultPositions);
    }

    /**
     * Loop the classes searching for a String static field named
     * staticFieldName and create an OR regeex like this:
     * (?:FIELD1|FIELD2|FIELD3)
     * 
     * @param classes
     *            classes to analyze
     * @param staticFieldName
     *            static field to concatenate
     * @return regex The regex
     */
    private String createRegex(Collection<TermDefinition> commandMap) {
        StringBuffer modifierRegex = new StringBuffer();
        Iterator<TermDefinition> i = commandMap.iterator();
        boolean first = true;
        while (i.hasNext()) {
            if (first) {
                modifierRegex.append("(?:(");
                first = false;
            } else {
                modifierRegex.append(")|(");
            }
            Pattern pattern = i.next().getPattern();
            modifierRegex.append(pattern.pattern());
        }
        modifierRegex.append("))");
        return modifierRegex.toString();
    }

    /**
     * @see org.apache.james.jspf.core.SPFRecordParser#parse(java.lang.String)
     */
    public SPF1Record parse(String spfRecord) throws PermErrorException,
            NoneException, NeutralException {

        LOGGER.debug("Start parsing SPF-Record: " + spfRecord);

        SPF1Record result = new SPF1Record();

        // check the version "header"
        if (spfRecord.toLowerCase().startsWith(SPF1Constants.SPF_VERSION1 + " ") || spfRecord.equalsIgnoreCase(SPF1Constants.SPF_VERSION1)) {
            if (!spfRecord.toLowerCase().startsWith(SPF1Constants.SPF_VERSION1 + " ")) throw new NeutralException("Empty SPF Record");
        } else {
            throw new NoneException("No valid SPF Record: " + spfRecord);
        }

        // extract terms
        String[] terms = termsSeparatorPattern.split(spfRecord.replaceFirst(
                SPF1Constants.SPF_VERSION1, ""));

        // cycle terms
        for (int i = 0; i < terms.length; i++) {
            if (terms[i].length() > 0) {
                Matcher termMatcher = termPattern.matcher(terms[i]);
                if (!termMatcher.matches()) {
                    throw new PermErrorException("Term [" + terms[i]
                            + "] is not syntactically valid: "
                            + termPattern.pattern());
                }

                // true if we matched a modifier, false if we matched a
                // directive
                String modifierString = termMatcher
                        .group(TERM_STEP_REGEX_MODIFIER_POS);

                if (modifierString != null) {
                    // MODIFIER
                    Modifier mod = (Modifier) lookupAndCreateTerm(termMatcher,
                            TERM_STEP_REGEX_MODIFIER_POS);

                    if (mod.enforceSingleInstance()) {
                        Iterator<Modifier> it = result.getModifiers().iterator();
                        while (it.hasNext()) {
                            if (it.next().getClass().equals(mod.getClass())) {
                                throw new PermErrorException("More than one "
                                        + modifierString
                                        + " found in SPF-Record");
                            }
                        }
                    }

                    result.getModifiers().add(mod);

                } else {
                    // DIRECTIVE
                    String qualifier = termMatcher
                            .group(TERM_STEP_REGEX_QUALIFIER_POS);

                    Object mech = lookupAndCreateTerm(termMatcher,
                            TERM_STEP_REGEX_MECHANISM_POS);

                    result.getDirectives().add(
                            new Directive(qualifier, (Mechanism) mech));

                }

            }
        }

        return result;
    }

    /**
     * @param res
     *            the MatchResult
     * @param start
     *            the position where the terms starts
     * @return
     * @throws PermErrorException
     */
    private Object lookupAndCreateTerm(Matcher res, int start)
            throws PermErrorException {
        for (int k = start + 1; k < res.groupCount(); k++) {
            if (res.group(k) != null && k != TERM_STEP_REGEX_QUALIFIER_POS) {
                TermDefinition c = (TermDefinition) matchResultPositions.get(k);
                Configuration subres = new MatcherBasedConfiguration(res, k, c
                        .getMatchSize());
                try {
                    return termsFactory.createTerm(c.getTermDef(), subres);
                } catch (InstantiationException e) {
                    e.printStackTrace();
                    // TODO is it ok to use a Runtime for this? Or should we use a PermError here?
                    throw new IllegalStateException("Unexpected error creating term: " + e.getMessage());
                }

            }
        }
        return null;
    }

}
