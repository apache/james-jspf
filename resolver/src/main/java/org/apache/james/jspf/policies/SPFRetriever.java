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

import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSResponse;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPF1Utils;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerDNSResponseListener;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.TempErrorException;
import org.apache.james.jspf.core.exceptions.TimeoutException;

import java.util.Iterator;
import java.util.List;

/**
 * Get the raw dns txt or spf entry which contains a spf entry
 */
public class SPFRetriever implements SPFChecker {
    
    /**
     * The TXT records of the domain, where RFC 7208 4.4 looks the record up ("type TXT only"): when
     * none is an SPF record, the records of the obsolete SPF type are read, as RFC 4408 4.4 allowed
     */
    private static final class SPFRecordHandlerDNSResponseListener implements SPFCheckerDNSResponseListener {

        /**
         * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation onDNSResponse(
                DNSResponse response, SPFSession session)
                throws PermErrorException,
                NoneException, TempErrorException,
                NeutralException {
            
            List<String> spfR;
            try {
                spfR = response.getResponse();
                String record = extractSPFRecord(spfR);
                if (record != null) {
                    session.setAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD, new SPF1Record(record));
                } else if (!CHECK_ONLY_TXT_RECORDS) {
                    String currentDomain = session.getCurrentDomain();
                    return new DNSLookupContinuation(new DNSRequest(currentDomain, DNSRequest.SPF), new SPFRetrieverDNSResponseListener());
                }
            } catch (TimeoutException e) {
                throw new TempErrorException("Timeout querying dns");
            }
            return null;
            
        }
        
    }

    /**
     * The records of the obsolete SPF type, of a domain whose TXT records hold no SPF record
     */
    private static final class SPFRetrieverDNSResponseListener implements SPFCheckerDNSResponseListener {

        /**
         * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation onDNSResponse(
                DNSResponse response, SPFSession session)
                throws PermErrorException, NoneException,
                TempErrorException, NeutralException {
            try {
                String record = extractSPFRecord(response.getResponse());
                if (record != null) {
                    session.setAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD, new SPF1Record(record));
                }
            } catch (TimeoutException e) {
                // RFC 7208 4.4: the record is looked up as "type TXT only": a DNS error of the obsolete SPF type is not one
            }
            return null;
        }
        
    }

	/**
	 * This is used for testing purpose. Setting this to true will skip the lookup of
	 * the obsolete SPF type, when no TXT record is an SPF record, and will simply check
	 * the TXT records.
	 */
	private static final boolean CHECK_ONLY_TXT_RECORDS = false;
    
    /**
     * Return the extracted SPF-Record 
     *  
     * @param spfR the List which holds TXT/SPF - Records
     * @return returnValue the extracted SPF-Record
     * @throws PermErrorException if more then one SPF - Record was found in the 
     *                            given List.
     */
    protected static String extractSPFRecord(List<String> spfR) throws PermErrorException {
        if (spfR == null || spfR.isEmpty()) return null;
        
        String returnValue = null;
        Iterator<String> all = spfR.iterator();
           
        while (all.hasNext()) {
            // DO NOT trim the result!
            String compare = all.next();

            // We trim the compare value only for the comparison
            if (compare.toLowerCase().trim().startsWith(SPF1Constants.SPF_VERSION1 + " ") || compare.trim().equalsIgnoreCase(SPF1Constants.SPF_VERSION1)) {
                if (returnValue == null) {
                    returnValue = compare;
                } else {
                    throw new PermErrorException(
                            "More than 1 SPF record found");
                }
            }
        }
        
        return returnValue;
    }
    

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation checkSPF(SPFSession spfData)
            throws PermErrorException, TempErrorException, NeutralException,
            NoneException {
        SPF1Record res = (SPF1Record) spfData.getAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD);
        if (res == null) {
            String currentDomain = spfData.getCurrentDomain();
            return new DNSLookupContinuation(new DNSRequest(currentDomain, DNSRequest.TXT), new SPFRecordHandlerDNSResponseListener());
        }
        return null;
    }

}