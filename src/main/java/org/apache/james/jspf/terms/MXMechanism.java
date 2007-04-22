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
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.util.DNSResolver;
import org.apache.james.jspf.util.SPFTermsRegexps;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represent the mx mechanism
 * 
 */
public class MXMechanism extends AMechanism {

    private static final String ATTRIBUTE_MX_RECORDS = "MXMechanism.mxRecords";
    private static final String ATTRIBUTE_CHECK_RECORDS = "MXMechanism.checkRecords";
    /**
     * ABNF: MX = "mx" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String REGEX = "[mM][xX]" + "(?:\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX + ")?" + "(?:"
            + DUAL_CIDR_LENGTH_REGEX + ")?";
    
    /**
     * @see org.apache.james.jspf.terms.AMechanism#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public void checkSPF(SPFSession spfData) throws PermErrorException,
            TempErrorException, NeutralException, NoneException{

        // update currentDepth
        spfData.increaseCurrentDepth();

        SPFChecker checker = new SPFChecker() {

            public void checkSPF(SPFSession spfData) throws PermErrorException,
                    TempErrorException, NeutralException, NoneException {

                // Get the right host.
                String host = expandHost(spfData);
                
                onDNSResponse(DNSResolver.lookup(dnsService, new DNSRequest(host, DNSService.MX)), spfData);
            }
            
        };
        
        DNSResolver.hostExpand(dnsService, macroExpand, getDomain(), spfData, MacroExpand.DOMAIN, checker);
    }

    /**
     * @see org.apache.james.jspf.core.Mechanism#onDNSResponse(org.apache.james.jspf.core.SPFSession)
     */
    private void onDNSResponse(DNSResponse response, SPFSession spfSession)
        throws PermErrorException, TempErrorException {
        try {
            
            List records = (List) spfSession.getAttribute(ATTRIBUTE_CHECK_RECORDS);
            List mxR = (List) spfSession.getAttribute(ATTRIBUTE_MX_RECORDS);
            
            if (records == null) {
            
                records = response.getResponse();
                
                if (records == null) {
                    // no mx record found
                    spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
                    return;
                }
                
                spfSession.setAttribute(ATTRIBUTE_CHECK_RECORDS, records);
                
            } else {
                
                List res = response.getResponse();
                
                if (res != null) {
                    if (mxR == null) {
                        mxR = new ArrayList();
                        spfSession.setAttribute(ATTRIBUTE_MX_RECORDS, mxR);
                    }
                    System.out.println("ADDALL: "+res);
                    mxR.addAll(res);
                }
                
            }

            // if the remote IP is an ipv6 we check ipv6 addresses, otherwise ip4
            boolean isIPv6 = IPAddr.isIPV6(spfSession.getIpAddress());

            String mx;
            while (records.size() > 0 && (mx = (String) records.remove(0)) != null && mx.length() > 0) {
                log.debug("Add MX-Record " + mx + " to list");
    
                this.onDNSResponse(DNSResolver.lookup(dnsService, new DNSRequest(mx, isIPv6 ? DNSService.AAAA : DNSService.A)), spfSession);
                return;
                
            }
                
            // no mx record found
            if (mxR == null || mxR.size() == 0) {
                spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
                return;
            }
            
            // get the ipAddress
            IPAddr checkAddress;
            checkAddress = IPAddr.getAddress(spfSession.getIpAddress(), isIPv6 ? getIp6cidr() : getIp4cidr());
            
            // clean up attributes
            spfSession.setAttribute(ATTRIBUTE_CHECK_RECORDS, null);
            spfSession.setAttribute(ATTRIBUTE_MX_RECORDS, null);
            spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.valueOf(checkAddressList(checkAddress, mxR, getIp4cidr())));
            return;
            
        } catch (DNSService.TimeoutException e) {
            spfSession.setAttribute(ATTRIBUTE_CHECK_RECORDS, null);
            spfSession.setAttribute(ATTRIBUTE_MX_RECORDS, null);
            throw new TempErrorException("Timeout querying the dns server");
        }
    }

    /**
     * @see org.apache.james.jspf.terms.AMechanism#toString()
     */
    public String toString() {
        return super.toString("mx");
    }

}
