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

import org.apache.james.jspf.dns.DNSLookupContinuation;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.dns.DNSRequest;
import org.apache.james.jspf.dns.DNSResponse;
import org.apache.james.jspf.dns.DNSService;
import org.apache.james.jspf.dns.SPFCheckerDNSResponseListener;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.util.SPFTermsRegexps;
import org.apache.james.jspf.wiring.MacroExpandEnabled;

import java.util.List;

/**
 * This class represent the exp modifier
 * 
 */
public class ExpModifier extends GenericModifier implements MacroExpandEnabled, SPFCheckerDNSResponseListener {

    private final class ExpandedExplanationChecker implements SPFChecker {
       
        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException, NoneException,
                TempErrorException, NeutralException {
            try {
                String exp = (String) spfData.getAttribute(ATTRIBUTE_EXPAND_EXPLANATION);
                String expandedExplanation = macroExpand.expand(exp, spfData, MacroExpand.EXPLANATION);
                spfData.setExplanation(expandedExplanation);
            } catch (PermErrorException e) {
                // ignore syntax error on explanation expansion
            }
            return null;
        }
    }


    private final class ExpandedChecker implements SPFChecker {
        
        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
                NoneException, TempErrorException, NeutralException {
            String host = macroExpand.expand(getHost(), spfData, MacroExpand.DOMAIN);

            return new DNSLookupContinuation(new DNSRequest(host, DNSRequest.TXT), ExpModifier.this);
        }
    }


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

    private MacroExpand macroExpand;

    private ExpandedChecker expandedChecker = new ExpandedChecker();

    private ExpandedExplanationChecker expandedExplanationChecker = new ExpandedExplanationChecker();

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
    protected DNSLookupContinuation checkSPFLogged(SPFSession spfData) throws PermErrorException, TempErrorException, NeutralException, NoneException {
        String host = getHost();
        
        // RFC4408 Errata: http://www.openspf.org/RFC_4408/Errata#empty-exp
        if (host == null) {
            return null;
        }

        // If we should ignore the explanation we don't have to run this class
        if (spfData.ignoreExplanation() == true)
            return null;
        
        // If the currentResult is not fail we have no need to run all these
        // methods!
        if (spfData.getCurrentResult()== null || !spfData.getCurrentResult().equals(SPF1Constants.FAIL))
            return null;

        spfData.pushChecker(expandedChecker);
        return macroExpand.checkExpand(host, spfData, MacroExpand.DOMAIN);
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
    
    /**
     * @see org.apache.james.jspf.dns.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.dns.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation onDNSResponse(DNSResponse lookup, SPFSession spfData) throws PermErrorException, TempErrorException, NeutralException, NoneException {
        try {
            List records = lookup.getResponse();
        
            if (records == null) {
                return null;
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
                if (exp.length()>=2 && exp.charAt(0) == '"' && exp.charAt(exp.length() -1 ) == '"') {
                    exp = exp.substring(1, exp.length() - 1);
                }

                spfData.setAttribute(ATTRIBUTE_EXPAND_EXPLANATION, exp);
                
                if ((exp != null) && (!exp.equals(""))) {
                    
                    try {
                        spfData.pushChecker(expandedExplanationChecker);
                        return macroExpand.checkExpand(exp, spfData, MacroExpand.EXPLANATION);
                    } catch (PermErrorException e) {
                        // ignore syntax error on explanation expansion
                    }
                }
                
            }
            

        } catch (DNSService.TimeoutException e) {
            // Nothing todo here.. just return null
        }
        return null;
    }
    
    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
       return "exp="+getHost();
    }

    /**
     * @see org.apache.james.jspf.wiring.MacroExpandEnabled#enableMacroExpand(org.apache.james.jspf.macro.MacroExpand)
     */
    public void enableMacroExpand(MacroExpand macroExpand) {
        this.macroExpand = macroExpand;
    }

}
