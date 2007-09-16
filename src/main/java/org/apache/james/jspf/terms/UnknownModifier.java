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


package org.apache.james.jspf.terms;

import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.SPFTermsRegexps;
import org.apache.james.jspf.core.exceptions.PermErrorException;

/**
 * This Class represent an Unknown Modifier
 * 
 */
public class UnknownModifier implements Modifier, ConfigurationEnabled {

    /**
     * ABNF: name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ) ABNF:
     * unknown-modifier = name "=" macro-string
     */
    public static final String REGEX = "(" + SPFTermsRegexps.ALPHA_PATTERN + "{1}"
            + "[A-Za-z0-9\\-\\_\\.]*" + ")" + "\\=("
            + SPFTermsRegexps.MACRO_STRING_REGEX + ")";

    /**
     * @see org.apache.james.jspf.terms.Modifier#run(org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException {
        return null;
    }

    /**
     * @see org.apache.james.jspf.terms.Modifier#enforceSingleInstance()
     */
    public boolean enforceSingleInstance() {
        return false;
    }

    /**
     * @see org.apache.james.jspf.terms.ConfigurationEnabled#config(Configuration)
     */
    public synchronized void config(Configuration params) throws PermErrorException {
        if (params.groupCount() >= 2 && params.group(1) != null) {
            String name = params.group(1).toLowerCase();
            if ("exp".equals(name) || "redirect".equals(name)) {
                throw new PermErrorException("exp and redirect are not valid names for unknown modifier: this probably means an invalid syntax for exp or redirect fallback to the unkown modifier.");
            }
        }
    }

}
