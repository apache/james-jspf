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

import org.apache.james.jspf.SPF;
import org.apache.james.jspf.core.Configurable;
import org.apache.james.jspf.core.LogEnabled;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.Mechanism;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.parser.SPF1Parser;
import org.apache.james.jspf.util.ConfigurationMatch;

/**
 * This class represent the incude mechanism
 * 
 */
public class IncludeMechanism implements Mechanism, Configurable, LogEnabled {

    /**
     * ABNF: include = "include" ":" domain-spec
     */
    public static final String REGEX = "[iI][nN][cC][lL][uU][dD][eE]" + "\\:"
            + SPF1Parser.DOMAIN_SPEC_REGEX;

    protected String host;
    
    protected Logger log;

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
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);      
        
        try {
            host = new MacroExpand(spfData, log).expandDomain(host);
        } catch (PermErrorException e) {
            throw new PermErrorException("Error in include modifier: " + host);
        }
            
        spfData.setCurrentDomain(host);
        
        // On includes we should not use the explanation of the included domain
        spfData.setIgnoreExplanation(true);
        
        String res = null;
        try {
             res = new SPF(spfData.getDnsProbe(),log).checkSPF(spfData).getResultChar();
          
        } catch (NoneException e) {
            throw new PermErrorException("included checkSPF returned NoneException");
        } catch (NeutralException e) {
            throw new PermErrorException("included checkSPF returned NeutralException");
        }
        
        // Reset the ignore
        spfData.setIgnoreExplanation(false);
        
        if (res == null) {
            throw new TempErrorException("included checkSPF returned null");
        } else if (res.equals(SPF1Constants.PASS)) {
            return true;
        } else if (res.equals(SPF1Constants.FAIL) || res.equals(SPF1Constants.SOFTFAIL) || res.equals(SPF1Constants.NEUTRAL)) {
            return false;
        } else {
            throw new TempErrorException("included checkSPF returned an Illegal result");
        }
            
    }

    /**
     * @see org.apache.james.jspf.core.Configurable#config(ConfigurationMatch)
     */
    public synchronized void config(ConfigurationMatch params) throws PermErrorException {
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
     * @see org.apache.james.jspf.core.LogEnabled#enableLogging(org.apache.james.jspf.core.Logger)
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
}
