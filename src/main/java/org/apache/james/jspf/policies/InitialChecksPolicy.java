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

package org.apache.james.jspf.policies;

import org.apache.james.jspf.SPF;
import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;

/**
 * Run the checks on the validity of the domain
 * This is an override filter to be executed as the first 
 * so it should be added as the last filter.
 */
public final class InitialChecksPolicy implements SPFChecker {
    
    public DNSLookupContinuation checkSPF(SPFSession spfData)
            throws PermErrorException, TempErrorException, NeutralException,
            NoneException {
        SPF1Record res = (SPF1Record) spfData.getAttribute(SPF.ATTRIBUTE_SPF1_RECORD);
        if (res == null) {

            // Initial checks (spec 4.3)
            String currentDomain = spfData.getCurrentDomain();
            if (currentDomain != null) {
                String[] labels = currentDomain.split("\\.");
                for (int i = 0; i < labels.length; i++) {
                    if (labels[i] != null && labels[i].length() > 63) {
                        throw new NoneException("Domain "+currentDomain+" is malformed (label longer than 63 characters)");
                    }
                }
            }
            
            if (spfData.getSenderDomain().indexOf('.') < 0) {
                throw new NoneException("Sender domain "+spfData.getSenderDomain()+" is not an FQDN.");
            }
            
            try {
                Name.fromString(spfData.getSenderDomain());
            } catch (TextParseException e) {
                throw new NoneException("Invalid sender domain: "+e.getMessage());
            }
        }
        return null;
    }
}