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

import org.apache.james.jspf.core.Configurable;
import org.apache.james.jspf.core.Configuration;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.Mechanism;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.util.SPFTermsRegexps;
import org.apache.james.jspf.wiring.LogEnabled;
import org.apache.james.jspf.wiring.MacroExpandEnabled;
import org.apache.james.jspf.wiring.SPFCheckEnabled;

/**
 * This class represent the incude mechanism
 * 
 */
public class IncludeMechanism implements Mechanism, Configurable, LogEnabled, SPFCheckEnabled, MacroExpandEnabled {

    /**
     * ABNF: include = "include" ":" domain-spec
     */
    public static final String REGEX = "[iI][nN][cC][lL][uU][dD][eE]" + "\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX;

    protected String host;
    
    protected Logger log;

    private SPFChecker spfChecker;

    private MacroExpand macroExpand;

    /**
     * Set the host which should be used for include
     * 
     * @param spfData
     *            The SPF1Data which should used
     * @return The host which should be included
     * @throws PermErrorException
     *             if an error is in the redirect modifier
     * @throws TempErrorException 
     *             if the dns return a temp error
     */
    public boolean run(SPF1Data spfData) throws PermErrorException, TempErrorException {
        String host = getHost();

        // update currentDepth
        spfData.increaseCurrentDepth();      
        
        // throws a PermErrorException that we can pass through
        host = macroExpand.expand(host, spfData, MacroExpand.DOMAIN);

        String prevRes = spfData.getCurrentResult();
        String prevHost = spfData.getCurrentDomain();
        
        try {
    
            spfData.setCurrentDomain(host);
            
            // On includes we should not use the explanation of the included domain
            spfData.setIgnoreExplanation(true);
            // set a null current result
            spfData.setCurrentResult(null);
            
            try {
                 spfChecker.checkSPF(spfData);
              
            } catch (NoneException e) {
                throw new PermErrorException("included checkSPF returned NoneException");
            } catch (NeutralException e) {
                throw new PermErrorException("included checkSPF returned NeutralException");
            }
            
            if (spfData.getCurrentResult() == null) {
                throw new TempErrorException("included checkSPF returned null");
            } else if (spfData.getCurrentResult().equals(SPF1Constants.PASS)) {
                return true;
            } else if (spfData.getCurrentResult().equals(SPF1Constants.FAIL) || spfData.getCurrentResult().equals(SPF1Constants.SOFTFAIL) || spfData.getCurrentResult().equals(SPF1Constants.NEUTRAL)) {
                return false;
            } else {
                throw new TempErrorException("included checkSPF returned an Illegal result");
            }
        } finally {
            // Reset the ignore
            spfData.setIgnoreExplanation(false);
            spfData.setCurrentDomain(prevHost);
            spfData.setCurrentResult(prevRes);
        }
            
    }

    /**
     * @see org.apache.james.jspf.core.Configurable#config(Configuration)
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
     * @see org.apache.james.jspf.wiring.LogEnabled#enableLogging(org.apache.james.jspf.core.Logger)
     */
    public void enableLogging(Logger logger) {
        this.log = logger;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return "include:"+getHost();
    }

    /**
     * @see org.apache.james.jspf.wiring.SPFCheckEnabled#enableSPFChecking(org.apache.james.jspf.core.SPFChecker)
     */
    public void enableSPFChecking(SPFChecker checker) {
        this.spfChecker = checker;
    }

    /**
     * @see org.apache.james.jspf.wiring.MacroExpandEnabled#enableMacroExpand(org.apache.james.jspf.macro.MacroExpand)
     */
    public void enableMacroExpand(MacroExpand macroExpand) {
        this.macroExpand = macroExpand;
    }
}
