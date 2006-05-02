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

import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.parser.SPF1Parser;

/**
 * This class represent the exp modifier
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public class ExpModifier extends GenericModifier {

    /**
     * ABNF: explanation = "exp" "=" domain-spec
     */
    public static final String REGEX = "[eE][xX][pP]" + "\\="
        + SPF1Parser.DOMAIN_SPEC_REGEX;

    private String defaultExplanation = "http://www.openspf.org/why.html?sender=%{S}&ip=%{I}";


    /**
     * Generate the explanation and set it in SPF1Data so it can be accessed
     * easy later if needed
     * 
     * @param spfData
     *            The SPF1Data which should used
     * @throws PermErrorException 
     * 
     */
    public String run(SPF1Data spfData) throws PermErrorException {
        String exp = null;
        String host = this.host;

        try {
            host = new MacroExpand(spfData).expandDomain(host);
            try {
                exp = spfData.getDnsProbe().getTxtCatType(host);
            } catch (NoneException e) {
                // TODO what should we do here?
            } catch (TempErrorException e) {
                // TODO what should we do here?
                e.printStackTrace();
            }
            
            if ((exp == null) || (exp.equals(""))) {
                spfData.setExplanation(new MacroExpand(spfData)
                        .expandExplanation(defaultExplanation));
            } else {
                spfData.setExplanation(new MacroExpand(spfData)
                        .expandExplanation(exp));
            }
        } catch (PermErrorException e) {
            spfData.setExplanation("");
            throw e;
        }
        return null;

    }

    /**
     * @see org.apache.james.jspf.core.Modifier#enforceSingleInstance()
     */
    public boolean enforceSingleInstance() {
        return true;
    }

}
