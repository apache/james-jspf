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
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.TempErrorException;
import org.apache.james.jspf.executor.FutureSPFResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Directive is a mechanism with a resulting qualifier.
 */
public class Directive implements SPFChecker {
    private static final Logger LOGGER = LoggerFactory.getLogger(Directive.class);

    private final class MechanismResultChecker implements SPFChecker {

        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException, TempErrorException,
                NeutralException, NoneException {
            Boolean res = (Boolean) spfData.getAttribute(ATTRIBUTE_MECHANISM_RESULT);
            if (res != null ? res.booleanValue() : true) {
                if (qualifier.equals("")) {
                    spfData.setCurrentResult(SPF1Constants.PASS);
                } else {
                    spfData.setCurrentResult(qualifier);
                }

                LOGGER.info("Processed directive matched: {} returned {}", Directive.this, spfData.getCurrentResult());
            } else {
                LOGGER.debug("Processed directive NOT matched: {}", this);
            }
            return null;
        }
        
    }

    public static final String ATTRIBUTE_MECHANISM_RESULT = "Mechanism.result";

    protected String qualifier = "+";

    private Mechanism mechanism = null;

    private MechanismResultChecker resultChecker;

    /**
     * Construct Directive
     * 
     * @param qualifier The qualifier to use. Valid qualifier are: +, -, ~, ?
     * @param mechanism The Mechanism 
     * @throws PermErrorException Get thrown if a PermError should returned
     */
    public Directive(String qualifier, Mechanism mechanism)
            throws PermErrorException {
        super();
        if (qualifier == null) {
            throw new PermErrorException("Qualifier cannot be null");
        }
        this.qualifier = qualifier;
        if (mechanism == null) {
            throw new PermErrorException("Mechanism cannot be null");
        }
        this.resultChecker  = new MechanismResultChecker();
        this.mechanism = mechanism;
    }

    /**
     * Run the Directive
     * 
     * @param spfSession The SPFSession to use
     * @return The qualifier which was returned
     * @throws PermErrorException get thrown if a PermError should returned
     * @throws TempErrorException get thrown if a TempError should returned
     * @throws NoneException get thrown if a NoneException should returned;
     * @throws NeutralException 
     */
    public DNSLookupContinuation checkSPF(SPFSession spfSession) throws PermErrorException,
            TempErrorException, NoneException, NeutralException {
        // if already have a current result we don't run this
        if (spfSession.getCurrentResult() == null && spfSession.getCurrentResultExpanded() == null) {

            spfSession.removeAttribute(ATTRIBUTE_MECHANISM_RESULT);

            spfSession.pushChecker(resultChecker);
            
            spfSession.pushChecker(mechanism);

        }
        return null;
    }

    /**
     * Return the Mechanism which should be run
     * 
     * @return the Mechanism
     */
    public Mechanism getMechanism() {
        return mechanism;
    }

    /**
     * Return the Qualifier
     * 
     * @return the qualifier
     */
    public String getQualifier() {
        return qualifier;
    }
    
    public String toString() {
        return qualifier + mechanism;
    }

}
