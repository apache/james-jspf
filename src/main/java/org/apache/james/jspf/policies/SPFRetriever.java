package org.apache.james.jspf.policies;

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

import java.util.Iterator;
import java.util.List;

/**
 * Get the raw dns txt or spf entry which contains a spf entry
 */
public class SPFRetriever implements Policy {
    /**
     * dns service
     */
    private final DNSService dns;


    /**
     * A new instance of the SPFRetriever
     * 
     * @param dns the dns service
     */
    public SPFRetriever(DNSService dns) {
        this.dns = dns;
    }


    /**
     * @see org.apache.james.jspf.policies.Policy#getSPFRecord(java.lang.String)
     */
    public SPF1Record getSPFRecord(String currentDomain) throws PermErrorException, TempErrorException, NoneException, NeutralException {
        // retrieve the SPFRecord
        String spfDnsEntry = retrieveSpfRecord(currentDomain);
        if (spfDnsEntry != null) {
            return new SPF1Record(spfDnsEntry);
        } else {
            return null;
        }
    }

    /**
     * Get the SPF-Record for a server
     * 
     * @param dns
     *            The dns service to query
     * @param hostname
     *            The hostname for which we want to retrieve the SPF-Record
     * @param spfVersion
     *            The SPF-Version which should used.
     * @return The SPF-Record if one is found.
     * @throws PermErrorException
     *             if more then one SPF-Record was found.
     * @throws TempErrorException
     *             if the lookup result was "TRY_AGAIN"
     */
    protected String retrieveSpfRecord(String hostname)
            throws PermErrorException, TempErrorException {

        try {
            // first check for SPF-Type records
            List spfR = dns.getRecords(hostname, DNSService.SPF);
            
            if (spfR == null || spfR.isEmpty()) {
                // do DNS lookup for TXT
                spfR = dns.getRecords(hostname, DNSService.TXT);
            }
    
            // process returned records
            if (spfR != null && !spfR.isEmpty()) {
                return extractSPFRecord(spfR);
            } else {
                return null;
            }
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying dns");
        }
    }
    
    /**
     * Return the extracted SPF-Record 
     *  
     * @param spfR the List which holds TXT/SPF - Records
     * @return returnValue the extracted SPF-Record
     * @throws PermErrorException if more then one SPF - Record was found in the 
     *                            given List.
     */
    protected String extractSPFRecord(List spfR) throws PermErrorException {
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
            if (compare.toLowerCase().trim().startsWith(SPF1Constants.SPF_VERSION + " ") || compare.trim().equalsIgnoreCase(SPF1Constants.SPF_VERSION)) {
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
     * Return the DNSService
     * 
     * @return the dns
     */
    protected DNSService getDNSService() {
        return dns;
    }


}