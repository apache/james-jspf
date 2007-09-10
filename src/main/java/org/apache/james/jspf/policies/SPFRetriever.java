package org.apache.james.jspf.policies;

import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPF1Utils;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerDNSResponseListener;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.dns.DNSRequest;
import org.apache.james.jspf.dns.DNSResponse;
import org.apache.james.jspf.dns.TimeoutException;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

import java.util.Iterator;
import java.util.List;

/**
 * Get the raw dns txt or spf entry which contains a spf entry
 */
public class SPFRetriever implements SPFChecker {
    
    private static final class SPFRecordHandlerDNSResponseListener implements SPFCheckerDNSResponseListener {

        /**
         * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.dns.DNSResponse, org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation onDNSResponse(
                DNSResponse response, SPFSession session)
                throws PermErrorException,
                NoneException, TempErrorException,
                NeutralException {
            
            List spfR;
            try {
                spfR = response.getResponse();
                String record = extractSPFRecord(spfR);
                if (record != null) {
                    session.setAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD, new SPF1Record(record));
                }
            } catch (TimeoutException e) {
                throw new TempErrorException("Timeout querying dns");
            }
            return null;
            
        }
        
    }

    private static final class SPFRetrieverDNSResponseListener implements SPFCheckerDNSResponseListener {

        /**
         * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.dns.DNSResponse, org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation onDNSResponse(
                DNSResponse response, SPFSession session)
                throws PermErrorException, NoneException,
                TempErrorException, NeutralException {
            try {
                List spfR = response.getResponse();
                
                if (spfR == null || spfR.isEmpty()) {
                    
                    String currentDomain = session.getCurrentDomain();
                    return new DNSLookupContinuation(new DNSRequest(currentDomain, DNSRequest.TXT), new SPFRecordHandlerDNSResponseListener());

                } else {
                    
                    String record = extractSPFRecord(spfR);
                    if (record != null) {
                        session.setAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD, new SPF1Record(record));
                    }
                    
                }
                
                return null;
                
            } catch (TimeoutException e) {
                throw new TempErrorException("Timeout querying dns");
            }
        }
        
    }

	/**
	 * This is used for testing purpose. Setting this to true will skip the initial
	 * lookups for SPF records and instead will simply check the TXT records.
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
    protected static String extractSPFRecord(List spfR) throws PermErrorException {
        if (spfR == null || spfR.isEmpty()) return null;
        
        String returnValue = null;
        Iterator all = spfR.iterator();
           
        while (all.hasNext()) {
            // DO NOT trim the result!
            String compare = all.next().toString();

            // TODO is this correct? we remove the first and last char if the
            // result has an initial " 
            // remove '"'
            if (compare.charAt(0)=='"') {
                compare = compare.toLowerCase().substring(1,
                        compare.length() - 1);
            }

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
            if (CHECK_ONLY_TXT_RECORDS) {
                return new DNSLookupContinuation(new DNSRequest(currentDomain, DNSRequest.TXT), new SPFRecordHandlerDNSResponseListener());
            } else {
                return new DNSLookupContinuation(new DNSRequest(currentDomain, DNSRequest.SPF), new SPFRetrieverDNSResponseListener());
            }
            
        }
        return null;
    }

}