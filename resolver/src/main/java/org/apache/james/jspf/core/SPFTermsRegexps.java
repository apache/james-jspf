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
 * This constants are used by Terms to define their matching rules.
 */
public interface SPFTermsRegexps {
    

    final String ALPHA_PATTERN = "[a-zA-Z]";

    final String MACRO_LETTER_PATTERN_EXP = "[rctlsodipvhRCTLSODIPVH]";

    final String MACRO_LETTER_PATTERN = "[lsodipvhLSODIPVH]";

    final String TRANSFORMERS_REGEX = "\\d*[r]?";

    final String DELEMITER_REGEX = "[\\.\\-\\+,/_\\=]";

    final String MACRO_LETTERS_REGEX = MACRO_LETTER_PATTERN_EXP + TRANSFORMERS_REGEX + DELEMITER_REGEX + "*";

    final String MACRO_EXPAND_REGEX = "\\%(?:\\{"
            + MACRO_LETTERS_REGEX + "\\}|\\%|\\_|\\-)";

    final String MACRO_LITERAL_REGEX = "[\\x21-\\x24\\x26-\\x7e]";

    /**
     * This is used by the MacroExpander
     */
    final String MACRO_STRING_REGEX_TOKEN = MACRO_EXPAND_REGEX
    + "|" + MACRO_LITERAL_REGEX + "{1}";


    /**
     * The macro-expands of a macro-string, with the macro-literals before each of them.
     *
     * Possessive: java.util.regex recurses once per iteration of a repeated group it may backtrack
     * into, which overflows the stack on a long macro-string, but loops over a possessive one. A
     * macro-literal is never "%", so a macro-string splits into its tokens one way only: there is
     * nothing to backtrack.
     */
    final String MACRO_EXPANDS_REGEX = "(?:" + MACRO_LITERAL_REGEX + "*+" + MACRO_EXPAND_REGEX + ")*+";

    /**
     * ABNF: macro-string = *( macro-expand / macro-literal )
     *
     * @deprecated not used by jSPF any more: it recurses once per character, which overflows the
     *             stack on a long macro-string. Use POSSESSIVE_MACRO_STRING_REGEX where nothing
     *             follows it, or DOMAIN_SPEC_REGEX.
     */
    @Deprecated
    final String MACRO_STRING_REGEX = "(?:" + MACRO_STRING_REGEX_TOKEN +")*";

    /**
     * ABNF: macro-string = *( macro-expand / macro-literal ), matched possessively (see
     * MACRO_EXPANDS_REGEX): it never gives a character back, so nothing that can be a macro-literal
     * or a macro-expand may follow it, as at the end of a term.
     */
    final String POSSESSIVE_MACRO_STRING_REGEX = MACRO_EXPANDS_REGEX + MACRO_LITERAL_REGEX + "*+";

    final String ALPHA_DIGIT_PATTERN = "[a-zA-Z0-9]";

    /**
     * ABNF: toplabel = ( *alphanum ALPHA *alphanum ) / ( 1*alphanum "-" *(
     * alphanum / "-" ) alphanum ) ; LDH rule plus additional TLD restrictions ;
     * (see [RFC3696], Section 2)
     */
    final String TOP_LABEL_REGEX = "(?:"
            + ALPHA_DIGIT_PATTERN + "*" + SPFTermsRegexps.ALPHA_PATTERN
            + "{1}" + ALPHA_DIGIT_PATTERN + "*|(?:"
            + ALPHA_DIGIT_PATTERN + "+" + "\\-" + "[a-zA-Z0-9\\-]*"
            + ALPHA_DIGIT_PATTERN + "))";

    /**
     * ABNF: domain-end = ( "." toplabel [ "." ] ) / macro-expand
     */
    final String DOMAIN_END_REGEX = "(?:\\." + TOP_LABEL_REGEX
            + "\\.?" + "|" + SPFTermsRegexps.MACRO_EXPAND_REGEX + ")";

    /**
     * ABNF: domain-spec = macro-string domain-end
     *
     * Matched without backtracking into the macro-expands (see MACRO_EXPANDS_REGEX): either the
     * macro-expands then macro-literals ending with "." toplabel [ "." ], or macro-literals and
     * macro-expands ending with a macro-expand. So a pattern appended to it cannot take a
     * macro-expand back: what follows must hold none, as the CIDR lengths the terms append.
     */
    final String DOMAIN_SPEC_REGEX = "((?:" + MACRO_EXPANDS_REGEX + MACRO_LITERAL_REGEX + "*\\."
            + TOP_LABEL_REGEX + "\\.?" + "|(?:" + MACRO_LITERAL_REGEX + "*+" + MACRO_EXPAND_REGEX + ")++))";

    /**
     * Spring MACRO_STRING from DOMAIN_END (domain end starts with .)
     *
     * @deprecated not used by jSPF any more: its macro-string group recurses once per character,
     *             which overflows the stack on a long domain-spec. Use DOMAIN_SPEC_REGEX.
     */
    @Deprecated
    final String DOMAIN_SPEC_REGEX_R = "("
            + SPFTermsRegexps.MACRO_STRING_REGEX + ")(" + DOMAIN_END_REGEX + ")";


}
