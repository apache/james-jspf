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
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.parser.SPF1Parser;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represent the ptr mechanism
 * 
 */
public class PTRMechanism extends GenericMechanism {

    /**
     * ABNF: PTR = "ptr" [ ":" domain-spec ]
     */
    public static final String REGEX = "[pP][tT][rR]" + "(?:\\:"
            + SPF1Parser.DOMAIN_SPEC_REGEX + ")?";

    /**
     * @see org.apache.james.jspf.core.Mechanism#run(org.apache.james.jspf.core.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException,
            TempErrorException {
        String compareDomain;
        ArrayList validatedHosts = new ArrayList();

        // update currentDepth
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

        // Get the right host.
        String host = expandHost(spfData);

        try {
            // Get PTR Records for the ipAddress which is provided by SPF1Data
            IPAddr ip = IPAddr.getAddress(spfData.getIpAddress());
            List domainList = spfData.getDnsProbe().getRecords(ip.getReverseIP(), DNSService.PTR);
    
            // No PTR records found
            if (domainList == null) return false;
    
            // check if the maximum lookup count is reached
            if (spfData.getDnsProbe().getRecordLimit() > 0 && domainList.size() > spfData.getDnsProbe().getRecordLimit()) {
                // Truncate the PTR list to getRecordLimit.
                // See #ptr-limit rfc4408 test
                domainList = domainList.subList(0, spfData.getDnsProbe().getRecordLimit()-1);
                // throw new PermErrorException("Maximum PTR lookup count reached");
            }
              
            for (int i = 0; i < domainList.size(); i++) {
                List aList = null;
                
                // check if the connecting ip is ip6. If so lookup AAAA record
                if (IPAddr.isIPV6(spfData.getIpAddress())) {
                    // Get aaaa record for this
                    aList = spfData.getDnsProbe().getRecords(
                            (String) domainList.get(i), DNSService.AAAA);
                } else {
                    // Get a record for this
                    aList = spfData.getDnsProbe().getRecords(
                            (String) domainList.get(i), DNSService.A);
                }
                if (aList != null) {
                    for (int j = 0; j < aList.size(); j++) {
                        if (aList.get(j).equals(spfData.getIpAddress())) {
                            validatedHosts.add(domainList.get(i));
                        }
                    }
                }
            }
    
            // Check if we match one of this ptr!
            for (int j = 0; j < validatedHosts.size(); j++) {
                compareDomain = (String) validatedHosts.get(j);
                
                if (compareDomain.equals(host)
                        || compareDomain.endsWith("." + host)) {
                    return true;
                }
            }
            
            return false;
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying the dns server");
        }

    }

}
