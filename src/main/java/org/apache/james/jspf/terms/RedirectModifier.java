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

import org.apache.james.jspf.core.LogEnabled;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.parser.SPF1Parser;

/**
 * This class represent the redirect modifier
 * 
 */
public class RedirectModifier extends GenericModifier implements LogEnabled {

    /**
     * ABNF: redirect = "redirect" "=" domain-spec
     */
    public static final String REGEX = "[rR][eE][dD][iI][rR][eE][cC][tT]"
            + "\\=" + SPF1Parser.DOMAIN_SPEC_REGEX;
    
    private Logger log;

    /**
     * Set the host which should be used for redirection and set it in SPF1Data
     * so it can be accessed easy later if needed
     * 
     * @param spfData
     *            The SPF1Data which should used
     * @return host The host to which we shuld redirect
     * @throws PermErrorException
     *             if an error is in the redirect modifier
     * @throws TempErrorException
     *             if an DNS problem accurred
     */
    public String run(SPF1Data spfData) throws PermErrorException,
            TempErrorException {
        // the redirect modifier is used only when we had no previous matches
        if (!spfData.isMatch()) {

            String host = getHost();

            // update currentDepth
            spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

            // throws a PermErrorException that we can pass through
            host = new MacroExpand(spfData, log).expandDomain(host);

            spfData.setCurrentDomain(host);

            String res = null;
            try {
                res = spfData.getSpfProbe().checkSPF(spfData).getResultChar();
            } catch (NoneException e) {
                // no spf record assigned to the redirect domain
                throw new PermErrorException(
                        "included checkSPF returned NoneException");
            } catch (NeutralException e) {
                throw new PermErrorException("included checkSPF returned NeutralException");
            
            } finally {
                //After the redirect we should not use the explanation from the orginal record
                spfData.setIgnoreExplanation(true);
            }

            return res;

        } else {
            // return null if we should not use the redirect at all
            return null;
        }
    }

    /**
     * @see org.apache.james.jspf.core.Modifier#enforceSingleInstance()
     */
    public boolean enforceSingleInstance() {
        return true;
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
        return "redirect="+getHost();
    }
}
