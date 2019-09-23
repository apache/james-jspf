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
import org.apache.james.jspf.core.MacroExpand;
import org.apache.james.jspf.core.MacroExpandEnabled;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPFCheckEnabled;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerExceptionCatcher;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.SPFTermsRegexps;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.TempErrorException;

/**
 * This class represent the incude mechanism
 * 
 */
public class IncludeMechanism implements Mechanism, ConfigurationEnabled, SPFCheckEnabled, MacroExpandEnabled {

    private final class ExpandedChecker implements SPFChecker {
      
        /**
        * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
        */
        public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
                TempErrorException {

            // throws a PermErrorException that we can pass through
            String host = macroExpand.expand(getHost(), spfData, MacroExpand.DOMAIN);
            
            spfData.setCurrentDomain(host);
            
            // On includes we should not use the explanation of the included domain
            spfData.setIgnoreExplanation(true);
            // set a null current result
            spfData.setCurrentResult(null);
            spfData.setCurrentResultExpanded(null);
            
            spfData.pushChecker(spfChecker);
            
            return null;
        }
    }

    private final class CleanupAndResultChecker implements SPFChecker, SPFCheckerExceptionCatcher {
        private String previousResult;
        private String previousResultExpanded;
        private String previousDomain;

        private void restoreSession(SPFSession spfData) {
            spfData.setIgnoreExplanation(false);
            spfData.setCurrentDomain(previousDomain);
            spfData.setCurrentResult(previousResult);
            spfData.setCurrentResultExpanded(previousResultExpanded);
        }
        
        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
                TempErrorException, NeutralException, NoneException {
            
            String currentResult = spfData.getCurrentResult();
            
            restoreSession(spfData);
            
            if (currentResult == null) {
                throw new TempErrorException("included checkSPF returned null");
            } else if (currentResult.equals(SPF1Constants.PASS)) {
                // TODO this won't work asynchronously
                spfData.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.TRUE);
            } else if (currentResult.equals(SPF1Constants.FAIL) || currentResult.equals(SPF1Constants.SOFTFAIL) || currentResult.equals(SPF1Constants.NEUTRAL)) {
                // TODO this won't work asynchronously
                spfData.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
            } else {
                throw new TempErrorException("included checkSPF returned an Illegal result");
            }

            return null;
        }

        /**
         * @see org.apache.james.jspf.core.SPFCheckerExceptionCatcher#onException(java.lang.Exception, org.apache.james.jspf.core.SPFSession)
         */
        public void onException(Exception exception, SPFSession session)
                throws PermErrorException, NoneException,
                TempErrorException, NeutralException {
            
            restoreSession(session);
            
            if (exception instanceof NeutralException) {
                throw new PermErrorException("included checkSPF returned NeutralException");
            } else if (exception instanceof NoneException) {
                throw new PermErrorException("included checkSPF returned NoneException");
            } else if (exception instanceof PermErrorException){
                throw (PermErrorException) exception;
            } else if (exception instanceof TempErrorException){
                throw (TempErrorException) exception;
            } else if (exception instanceof RuntimeException){
                throw (RuntimeException) exception;
            } else {
                throw new IllegalStateException(exception.getMessage());
            }
        }

        public SPFChecker init(SPFSession spfSession) {
            // TODO understand what exactly we have to do now that spfData is a session
            // and contains much more than the input data.
            // do we need to create a new session at all?
            // do we need to backup the session attributes and restore them?
            this.previousResult = spfSession.getCurrentResult();
            this.previousDomain = spfSession.getCurrentDomain();
            this.previousResultExpanded = spfSession.getCurrentResultExpanded();
            return this;
        }
    }

    /**
     * ABNF: include = "include" ":" domain-spec
     */
    public static final String REGEX = "[iI][nN][cC][lL][uU][dD][eE]" + "\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX;

    protected String host;

    private SPFChecker spfChecker;

    private MacroExpand macroExpand;

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException, TempErrorException, NoneException, NeutralException {
        // update currentDepth
        spfData.increaseCurrentDepth();
        
        SPFChecker cleanupAndResultHandler = new CleanupAndResultChecker().init(spfData);
        spfData.pushChecker(cleanupAndResultHandler);
        
        spfData.pushChecker(new ExpandedChecker());
        return macroExpand.checkExpand(getHost(), spfData, MacroExpand.DOMAIN);
    }

    /**
     * @see org.apache.james.jspf.terms.ConfigurationEnabled#config(Configuration)
     */
    public synchronized void config(Configuration params) throws PermErrorException {
        if (params.groupCount() == 0) {
            throw new PermErrorException("Include mechanism without an host");
        }
        host = params.group(1);
    }

    /**
     * @return Returns the host.
     */
    protected synchronized String getHost() {
        return host;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return "include:"+getHost();
    }

    /**
     * @see org.apache.james.jspf.core.SPFCheckEnabled#enableSPFChecking(org.apache.james.jspf.core.SPFChecker)
     */
    public void enableSPFChecking(SPFChecker checker) {
        this.spfChecker = checker;
    }

    /**
     * @see org.apache.james.jspf.core.MacroExpandEnabled#enableMacroExpand(org.apache.james.jspf.core.MacroExpand)
     */
    public void enableMacroExpand(MacroExpand macroExpand) {
        this.macroExpand = macroExpand;
    }
}
