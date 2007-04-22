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

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSResponse;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.util.DNSResolver;
import org.apache.james.jspf.util.SPFTermsRegexps;
import org.apache.james.jspf.wiring.DNSServiceEnabled;
import org.apache.james.jspf.wiring.MacroExpandEnabled;

import java.util.List;

/**
 * This class represent the exp modifier
 * 
 */
public class ExpModifier extends GenericModifier implements DNSServiceEnabled, MacroExpandEnabled {

    private static final String ATTRIBUTE_EXPAND_EXPLANATION = "ExpModifier.ExpandExplanation";

    /**
     * ABNF: explanation = "exp" "=" domain-spec
     * 
     * NOTE: the last +"?" has been added to support RFC4408 ERRATA for the EXP modifier.
     * An "exp=" should not result in a perm error but should be ignored.
     * Errata: http://www.openspf.org/RFC_4408/Errata#empty-exp
     */
    public static final String REGEX = "[eE][xX][pP]" + "\\="
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX+"?";

    private DNSService dnsService;
    
    private MacroExpand macroExpand;

    /**
     * Generate the explanation and set it in SPF1Data so it can be accessed
     * easy later if needed
     * 
     * @param spfData
     *            The SPF1Data which should used
     * @throws PermErrorException 
     * @throws TempErrorException 
     * @throws NoneException 
     * @throws NeutralException 
     */
    protected void checkSPFLogged(SPFSession spfData) throws PermErrorException, TempErrorException, NeutralException, NoneException {
        String host = getHost();
        
        // RFC4408 Errata: http://www.openspf.org/RFC_4408/Errata#empty-exp
        if (host == null) {
            return;
        }

        // If we should ignore the explanation we don't have to run this class
        if (spfData.ignoreExplanation() == true)
            return;
        
        // If the currentResult is not fail we have no need to run all these
        // methods!
        if (spfData.getCurrentResult()== null || !spfData.getCurrentResult().equals(SPF1Constants.FAIL))
            return;

        DNSResolver.hostExpand(dnsService, macroExpand, host, spfData, MacroExpand.DOMAIN, new SPFChecker() {

            public void checkSPF(SPFSession spfData) throws PermErrorException,
                    NoneException, TempErrorException, NeutralException {
                String host = macroExpand.expand(getHost(), spfData, MacroExpand.DOMAIN);

                onDNSResponse(DNSResolver.lookup(dnsService, new DNSRequest(host, DNSService.TXT)), spfData);
            }
            
        });
    }

    /**
     * Get TXT records as a string
     * 
     * @param dns The DNSService to query
     * @param strServer
     *            The hostname for which we want to retrieve the TXT-Record
     * @return String which reflect the TXT-Record
     * @throws PermErrorException
     *             if more then one TXT-Record for explanation was found
     * @throws NoneException 
     * @throws NeutralException 
     * @throws TempErrorException 
     * @throws TempErrorException
     *             if the lookup result was "TRY_AGAIN"
     */
    public void onDNSResponse(DNSResponse lookup, SPFSession spfData) throws PermErrorException, TempErrorException, NeutralException, NoneException {
        try {
            List records = lookup.getResponse();
        
            if (records == null) {
                return;
            }
    
            // See SPF-Spec 6.2
            //
            // If domain-spec is empty, or there are any DNS processing errors (any RCODE other than 0), 
            // or if no records are returned, or if more than one record is returned, or if there are syntax 
            // errors in the explanation string, then proceed as if no exp modifier was given.   
            if (records.size() > 1) {
                
                log.debug("More then one TXT-Record found for explanation");
                // Only catch the error and return null
                
            } else {
                
                String exp = (String) records.get(0);

                spfData.setAttribute(ATTRIBUTE_EXPAND_EXPLANATION, exp);
                
                if ((exp != null) && (!exp.equals(""))) {
                    
                    try {
                        DNSResolver.hostExpand(dnsService, macroExpand, exp, spfData, MacroExpand.EXPLANATION, new SPFChecker() {
    
                            public void checkSPF(SPFSession spfData)
                                    throws PermErrorException, NoneException,
                                    TempErrorException, NeutralException {
                                String exp = (String) spfData.getAttribute(ATTRIBUTE_EXPAND_EXPLANATION);
                                String expandedExplanation = macroExpand.expand(exp, spfData, MacroExpand.EXPLANATION);
                                spfData.setExplanation(expandedExplanation);
                            }
                            
                        });
                    } catch (PermErrorException e) {
                        // ignore syntax error on explanation expansion
                    }
                }
                
            }
            

        } catch (DNSService.TimeoutException e) {
            // Nothing todo here.. just return null
            return;
        }
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
       return "exp="+getHost();
    }

    /**
     * @see org.apache.james.jspf.wiring.DNSServiceEnabled#enableDNSService(org.apache.james.jspf.core.DNSService)
     */
    public void enableDNSService(DNSService service) {
        this.dnsService = service;
    }


    /**
     * @see org.apache.james.jspf.wiring.MacroExpandEnabled#enableMacroExpand(org.apache.james.jspf.macro.MacroExpand)
     */
    public void enableMacroExpand(MacroExpand macroExpand) {
        this.macroExpand = macroExpand;
    }

}
