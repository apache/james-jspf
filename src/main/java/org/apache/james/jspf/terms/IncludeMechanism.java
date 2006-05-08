/***********************************************************************
 * Copyright (c) 2006 The Apache Software Foundation.             *
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

package org.apache.james.jspf.terms;

import org.apache.james.jspf.SPF;
import org.apache.james.jspf.core.Configurable;
import org.apache.james.jspf.core.Mechanism;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.parser.SPF1Parser;
import org.apache.james.jspf.util.ConfigurationMatch;

/**
 * This class represent the incude mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 */
public class IncludeMechanism implements Mechanism, Configurable {

    /**
     * ABNF: include = "include" ":" domain-spec
     */
    public static final String REGEX = "[iI][nN][cC][lL][uU][dD][eE]" + "\\:"
            + SPF1Parser.DOMAIN_SPEC_REGEX;

    private String host;

    /**
     * Set the host which should be used for include
     * 
     * @param spfData
     *            The SPF1Data which should used
     * @return The host which should be included
     * @throws PermErrorException
     *             if an error is in the redirect modifier
     * @throws TempErrorException 
     * @throws NoneException 
     */
    public boolean run(SPF1Data spfData) throws PermErrorException, TempErrorException, NoneException {
        String host = this.host;

        // update currentDepth
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);      
        
        try {
            host = new MacroExpand(spfData).expandDomain(host);
        } catch (Exception e) {
            throw new PermErrorException("Error in include modifier: " + host);
        }
            
        spfData.setCurrentDomain(host);
        
        // On includes we should not use the explanation of the included domain
        spfData.setIgnoreExplanation(true);
        
        String res = null;
        try {
            res = new SPF(spfData.getDnsProbe()).checkSPF(spfData);
        } catch (NoneException e) {
            throw new PermErrorException("included checkSPF returned NoneException");
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
    public void config(ConfigurationMatch params) throws PermErrorException {
        if (params.groupCount() == 0) {
            throw new PermErrorException("Include mechanism without an host");
        }
        host = params.group(1);
    }

}
