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
 * Get the raw dns txt entry which contains a spf entry
 */
public class SPFRetriever extends AbstractNestedPolicy {
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
     * @see org.apache.james.jspf.policies.AbstractNestedPolicy#setChildPolicy(org.apache.james.jspf.policies.Policy)
     */
    public void setChildPolicy(Policy children) {
        if (children != null) {
            throw new IllegalStateException("Cannot set a child policy for SPFRetriever");
        }
    }


    /**
     * @see org.apache.james.jspf.policies.AbstractNestedPolicy#getSPFRecordOverride(java.lang.String)
     */
    protected SPF1Record getSPFRecordOverride(String currentDomain) throws PermErrorException, TempErrorException, NoneException, NeutralException {
        // retrieve the SPFRecord
        String spfDnsEntry = retrieveSpfRecord(currentDomain);
        if (spfDnsEntry != null) {
            return new SPF1Record(spfDnsEntry);
        } else {
            return null;
        }
    }

    /**
     * Get the SPF-Record for a server given it's version
     * 
     * TODO: support SPF Records too. This will be done if dnsjava support it!
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
    private String retrieveSpfRecord(String hostname)
            throws PermErrorException, TempErrorException {

        String returnValue = null;
        try {
            List spfR = dns.getRecords(hostname, DNSService.SPF);
            if (spfR == null || spfR.isEmpty()) {
                // do DNS lookup for TXT
                spfR = dns.getRecords(hostname, DNSService.TXT);
            }
    
            // process returned records
            if (spfR != null && !spfR.isEmpty()) {
    
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
                                    "More than 1 SPF record found for host: " + hostname);
                        }
                    }
                }
            }
            return returnValue;
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying dns");
        }
    }

}