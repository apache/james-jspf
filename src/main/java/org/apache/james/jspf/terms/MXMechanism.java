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
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.util.SPFTermsRegexps;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represent the mx mechanism
 * 
 */
public class MXMechanism extends AMechanism {

    /**
     * ABNF: MX = "mx" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String REGEX = "[mM][xX]" + "(?:\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX + ")?" + "(?:"
            + DUAL_CIDR_LENGTH_REGEX + ")?";

    /**
     * 
     * @throws NoneException 
     * @see org.apache.james.jspf.core.GenericMechanism#run(org.apache.james.jspf.core.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException,
            TempErrorException{
        IPAddr checkAddress;

        // update currentDepth
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

        // Get the right host.
        String host = expandHost(spfData);

        // get the ipAddress
        checkAddress = IPAddr.getAddress(spfData.getIpAddress(), getIp4cidr());
        
        List mxRecords = getMXRecords(spfData.getDnsProbe(), host);

        // no mx record found
        if (mxRecords == null) return false;
          
        if (checkAddressList(checkAddress, mxRecords, getIp4cidr())) {
            return true;
        }

        // No match found
        return false;
    }


    /**
     * @see org.apache.james.jspf.core.DNSService#getMXRecords(java.lang.String,
     *      int)
     */
    public List getMXRecords(DNSService dnsProbe, String domainName)
            throws PermErrorException, TempErrorException {
        try {
            List mxR = null;
            List records = dnsProbe.getRecords(domainName, DNSService.MX);
    
            if (records == null) {
                return null;
            }
            
            for (int i = 0; i < records.size(); i++) {
                String mx = (String) records.get(i);
                
                if (mx != null && mx.length() > 0) {
                    log.debug("Add MX-Record " + mx + " to list");
        
                    List res = dnsProbe.getRecords(mx, DNSService.A);
                    if (res != null) {
                        if (mxR == null) {
                            mxR = new ArrayList();
                        }
                        mxR.addAll(res);
                    }
                }
            }
            
            return mxR != null && mxR.size() > 0 ? mxR : null;
        } catch (DNSService.TimeoutException e) {
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
