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
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.util.DNSResolver;
import org.apache.james.jspf.util.SPFTermsRegexps;
import org.apache.james.jspf.wiring.DNSServiceEnabled;

import java.util.List;

/**
 * This class represent the exists mechanism
 */
public class ExistsMechanism extends GenericMechanism implements DNSServiceEnabled {

    /**
     * ABNF: exists = "exists" ":" domain-spec
     */
    public static final String REGEX = "[eE][xX][iI][sS][tT][sS]" + "\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX;
    
    private DNSService dnsService;

    /**
     * 
     * @see org.apache.james.jspf.core.GenericMechanism#run(org.apache.james.jspf.core.SPFSession)
     */
    public boolean run(SPFSession spfData) throws PermErrorException,
            TempErrorException {
        // update currentDepth
        spfData.increaseCurrentDepth();

        String host = expandHost(spfData);

        return this.onDNSResponse(DNSResolver.lookup(dnsService, new DNSRequest(host,DNSService.A)), spfData);
    }

    /**
     * @see org.apache.james.jspf.core.Mechanism#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public boolean onDNSResponse(DNSResponse response, SPFSession spfSession) throws PermErrorException, TempErrorException {
        List aRecords;
        
        try {
            aRecords = response.getResponse();
        } catch (DNSService.TimeoutException e) {
            return false;
        }
        
        if (aRecords != null && aRecords.size() > 0) {
            return true;
        }
        
        // No match found
        return false;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return "exists:"+getDomain();
    }

    /**
     * @see org.apache.james.jspf.wiring.DNSServiceEnabled#enableDNSService(org.apache.james.jspf.core.DNSService)
     */
    public void enableDNSService(DNSService service) {
        this.dnsService = service;
    }

}
