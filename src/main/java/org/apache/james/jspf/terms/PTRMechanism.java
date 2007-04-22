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
import org.apache.james.jspf.core.Directive;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerDNSResponseListener;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.util.DNSResolver;
import org.apache.james.jspf.util.SPFTermsRegexps;
import org.apache.james.jspf.wiring.DNSServiceEnabled;

import java.util.List;

/**
 * This class represent the ptr mechanism
 * 
 */
public class PTRMechanism extends GenericMechanism implements DNSServiceEnabled, SPFCheckerDNSResponseListener {

    private static final String ATTRIBUTE_CURRENT_DOMAIN = "PTRMechanism.currentDomain";

    private static final String ATTRIBUTE_EXPANDED_HOST = "PTRMechanism.expandedHost";

    private static final String ATTRIBUTE_DOMAIN_LIST = "PTRMechanism.domainListCheck";

    /**
     * ABNF: PTR = "ptr" [ ":" domain-spec ]
     */
    public static final String REGEX = "[pP][tT][rR]" + "(?:\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX + ")?";
    
    private DNSService dnsService;

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public void checkSPF(SPFSession spfData) throws PermErrorException,
            TempErrorException, NeutralException, NoneException {
        // update currentDepth
        spfData.increaseCurrentDepth();

        
        SPFChecker checker = new SPFChecker() {

            public void checkSPF(SPFSession spfData) throws PermErrorException,
                    TempErrorException, NeutralException, NoneException {

                // Get PTR Records for the ipAddress which is provided by SPF1Data
                IPAddr ip = IPAddr.getAddress(spfData.getIpAddress());

                // Get the right host.
                String host = expandHost(spfData);
                
                spfData.setAttribute(ATTRIBUTE_EXPANDED_HOST, host);

                DNSResolver.lookup(dnsService, new DNSRequest(ip.getReverseIP(), DNSService.PTR), spfData, PTRMechanism.this);
            }
            
        };
        
        spfData.pushChecker(checker);
        DNSResolver.hostExpand(dnsService, macroExpand, getDomain(), spfData, MacroExpand.DOMAIN);
    }

    /**
     * @see org.apache.james.jspf.wiring.DNSServiceEnabled#enableDNSService(org.apache.james.jspf.core.DNSService)
     */
    public void enableDNSService(DNSService service) {
        this.dnsService = service;
    }

    /**
     * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public void onDNSResponse(DNSResponse response, SPFSession spfSession)
            throws PermErrorException, TempErrorException, NoneException, NeutralException {
        
        List domainList = (List) spfSession.getAttribute(ATTRIBUTE_DOMAIN_LIST);
        try {
            if (domainList == null) {
            
                domainList = response.getResponse();
                
                // No PTR records found
                if (domainList == null) {
                    spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
                    return;
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
                        if (aList.get(j).equals(spfSession.getIpAddress())) {
                            
                            if (compareDomain.equals(host)
                                    || compareDomain.endsWith("." + host)) {
                                spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.TRUE);
                                return;
                            }
                            
                        }
                    }
                }
            
            }
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying the dns server");
        }
        

        try {

            if (domainList.size() > 0) {
                String currentDomain = (String) domainList.remove(0);
        
                DNSRequest dnsRequest;
                // check if the connecting ip is ip6. If so lookup AAAA record
                if (IPAddr.isIPV6(spfSession.getIpAddress())) {
                    // Get aaaa record for this
                    dnsRequest = new DNSRequest(currentDomain, DNSService.AAAA);
                } else {
                    // Get a record for this
                    dnsRequest = new DNSRequest(currentDomain, DNSService.A);
                }
                
                spfSession.setAttribute(ATTRIBUTE_CURRENT_DOMAIN, currentDomain);
                
                DNSResolver.lookup(dnsService, dnsRequest, spfSession, PTRMechanism.this);
                return;
            } else {
                spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
                return;
            }

        } finally {
            spfSession.setAttribute(ATTRIBUTE_DOMAIN_LIST, null);
            spfSession.setAttribute(ATTRIBUTE_CURRENT_DOMAIN, null);
        }

    }


}
