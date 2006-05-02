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

package org.apache.james.jspf.modifier;

import org.apache.james.jspf.MacroExpand;
import org.apache.james.jspf.NoneException;
import org.apache.james.jspf.PermErrorException;
import org.apache.james.jspf.SPF;
import org.apache.james.jspf.SPF1Data;
import org.apache.james.jspf.SPF1Parser;
import org.apache.james.jspf.TempErrorException;

/**
 * This class represent the redirect modifier
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public class RedirectModifier extends GenericModifier {

    /**
     * ABNF: redirect = "redirect" "=" domain-spec
     */
    public static final String REGEX = "[rR][eE][dD][iI][rR][eE][cC][tT]" + "\\=" + SPF1Parser.DOMAIN_SPEC_REGEX;

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
     */
    public String run(SPF1Data spfData) throws PermErrorException, TempErrorException {
        // the redirect modifier is used only when we had no previous matches
        if (!spfData.isMatch()) {
            
            String host = this.host;
            
            // update currentDepth
            spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);
    
            try {
                host = new MacroExpand(spfData).expandDomain(host);
            } catch (Exception e) {
                throw new PermErrorException("Error in redirect modifier: " + host);
            }
            
            spfData.setCurrentDomain(host);
            
            String res = null;
            try {
                res = new SPF(spfData.getDnsProbe()).checkSPF(spfData);
            } catch (NoneException e) {
                throw new PermErrorException("included checkSPF returned NoneException");
            }
            
            return res;
            
        } else {
            return null;
        }
    }

    /**
     * @see org.apache.james.jspf.modifier.Modifier#enforceSingleInstance()
     */
    public boolean enforceSingleInstance() {
        return true;
    }

}
