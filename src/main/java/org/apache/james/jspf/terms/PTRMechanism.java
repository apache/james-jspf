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
import org.apache.james.jspf.core.Directive;
import org.apache.james.jspf.core.IPAddr;
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
import org.apache.james.jspf.wiring.DNSServiceEnabled;

import java.util.List;

/**
 * This class represent the ptr mechanism
 * 
 */
public class PTRMechanism extends GenericMechanism implements DNSServiceEnabled, SPFCheckerDNSResponseListener {

    private final class ExpandedChecker implements SPFChecker {
        private CleanupChecker cleanupChecker = new CleanupChecker();

        private final class CleanupChecker implements SPFChecker {

            /**
             * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
             */
            public DNSLookupContinuation checkSPF(SPFSession spfData)
                    throws PermErrorException, TempErrorException,
                    NeutralException, NoneException {
                spfData.removeAttribute(ATTRIBUTE_DOMAIN_LIST);
                spfData.removeAttribute(ATTRIBUTE_CURRENT_DOMAIN);
                return null;
            }
        }

        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
                TempErrorException, NeutralException, NoneException {

            // Get PTR Records for the ipAddress which is provided by SPF1Data
            IPAddr ip = IPAddr.getAddress(spfData.getIpAddress());

            // Get the right host.
            String host = expandHost(spfData);
            
            spfData.setAttribute(ATTRIBUTE_EXPANDED_HOST, host);
            
            spfData.pushChecker(cleanupChecker);

            return new DNSLookupContinuation(new DNSRequest(ip.getReverseIP(), DNSRequest.PTR), PTRMechanism.this);
        }
    }

    private static final String ATTRIBUTE_CURRENT_DOMAIN = "PTRMechanism.currentDomain";

    private static final String ATTRIBUTE_EXPANDED_HOST = "PTRMechanism.expandedHost";

    private static final String ATTRIBUTE_DOMAIN_LIST = "PTRMechanism.domainListCheck";

    /**
     * ABNF: PTR = "ptr" [ ":" domain-spec ]
     */
    public static final String REGEX = "[pP][tT][rR]" + "(?:\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX + ")?";
    
    private DNSService dnsService;

    private SPFChecker expandedChecker = new ExpandedChecker();

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
            TempErrorException, NeutralException, NoneException {
        // update currentDepth
        spfData.increaseCurrentDepth();

        spfData.pushChecker(expandedChecker);
        return macroExpand.checkExpand(getDomain(), spfData, MacroExpand.DOMAIN);
    }

    /**
     * @see org.apache.james.jspf.wiring.DNSServiceEnabled#enableDNSService(org.apache.james.jspf.dns.DNSService)
     */
    public void enableDNSService(DNSService service) {
        this.dnsService = service;
    }

    /**
     * @see org.apache.james.jspf.dns.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.dns.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation onDNSResponse(DNSResponse response, SPFSession spfSession)
            throws PermErrorException, TempErrorException, NoneException, NeutralException {
        
        List domainList = (List) spfSession.getAttribute(ATTRIBUTE_DOMAIN_LIST);
        try {
            if (domainList == null) {
            
                domainList = response.getResponse();
                
                // No PTR records found
                if (domainList == null) {
                    spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
                    return null;
                }
        
                // check if the maximum lookup count is reached
                if (dnsService.getRecordLimit() > 0 && domainList.size() > dnsService.getRecordLimit()) {
                    // Truncate the PTR list to getRecordLimit.
                    // See #ptr-limit rfc4408 test
                    domainList = domainList.subList(0, dnsService.getRecordLimit()-1);
                    // throw new PermErrorException("Maximum PTR lookup count reached");
                }
                
                spfSession.setAttribute(ATTRIBUTE_DOMAIN_LIST, domainList);
                
            } else {

                String compareDomain = (String) spfSession.getAttribute(ATTRIBUTE_CURRENT_DOMAIN);
                String host = (String) spfSession.getAttribute(ATTRIBUTE_EXPANDED_HOST);
    
                List aList = response.getResponse();
    

                if (aList != null) {
                    for (int j = 0; j < aList.size(); j++) {
                        // Added the IPAddr parsing/toString to have matching in IPV6 multiple ways to 
                        if (IPAddr.getAddress((String) aList.get(j)).getIPAddress().equals(IPAddr.getAddress(spfSession.getIpAddress()).getIPAddress())) {
                            
                            if (compareDomain.equals(host)
                                    || compareDomain.endsWith("." + host)) {
                                spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.TRUE);
                                return null;
                            }
                        }
                    }
                }
            
            }
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying the dns server");
        }
        

        if (domainList.size() > 0) {
            String currentDomain = (String) domainList.remove(0);
    
            DNSRequest dnsRequest;
            // check if the connecting ip is ip6. If so lookup AAAA record
            if (IPAddr.isIPV6(spfSession.getIpAddress())) {
                // Get aaaa record for this
                dnsRequest = new DNSRequest(currentDomain, DNSRequest.AAAA);
            } else {
                // Get a record for this
                dnsRequest = new DNSRequest(currentDomain, DNSRequest.A);
            }
            
            spfSession.setAttribute(ATTRIBUTE_CURRENT_DOMAIN, currentDomain);
            
            return new DNSLookupContinuation(dnsRequest, PTRMechanism.this);
        } else {
            spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
            return null;
        }

    }


}
