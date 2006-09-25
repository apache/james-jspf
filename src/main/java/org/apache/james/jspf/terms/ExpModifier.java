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

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.LogEnabled;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.parser.SPF1Parser;

import java.util.List;

/**
 * This class represent the exp modifier
 * 
 */
public class ExpModifier extends GenericModifier implements LogEnabled {

    /**
     * ABNF: explanation = "exp" "=" domain-spec
     */
    public static final String REGEX = "[eE][xX][pP]" + "\\="
            + SPF1Parser.DOMAIN_SPEC_REGEX;

    private Logger log;

    /**
     * Generate the explanation and set it in SPF1Data so it can be accessed
     * easy later if needed
     * 
     * @param spfData
     *            The SPF1Data which should used
     * 
     */
    public String run(SPF1Data spfData) {
        String exp = null;
        String host = getHost();

        // If the currentResult is not fail we have no need to run all these
        // methods!
        if (spfData.getCurrentResult()== null || !spfData.getCurrentResult().equals(SPF1Constants.FAIL))
            return null;
        
        // If we should ignore the explanation we don't have to run this class
        if (spfData.ignoreExplanation() == true)
            return null;

        try {
            host = new MacroExpand(spfData, log).expandDomain(host);
            try {
                exp = getTxtCatType(spfData.getDnsProbe(), host);
            } catch (TempErrorException e) {
                // Nothing todo here.. just return null
                return null;
            }

            if ((exp != null) && (!exp.equals(""))) {
                spfData.setExplanation(new MacroExpand(spfData, log)
                        .expandExplanation(exp));
            } 
        } catch (PermErrorException e) {
            // Only catch the error and return null
            return null;
        }
        return null;
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
     * Get TXT records as a string
     * 
     * @param dns The DNSService to query
     * @param strServer
     *            The hostname for which we want to retrieve the TXT-Record
     * @return String which reflect the TXT-Record
     * @throws PermErrorException
     *             if the hostname is not resolvable
     * @throws TempErrorException
     *             if the lookup result was "TRY_AGAIN"
     */
    public String getTxtCatType(DNSService dns, String strServer) throws TempErrorException {
        try {
            List records = dns.getRecords(strServer, DNSService.TXT);
        
            if (records == null) {
                return null;
            }
    
            log.debug("Concatenating " + records.size() + " TXT-Records to one String");
    
            StringBuffer txtData = new StringBuffer();
            for (int i = 0; i < records.size(); i++) {
                txtData.append(records.get(i));
            }
            return txtData.toString();
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying dns server");
        }
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
       return "exp="+getHost();
    }

}
