package org.apache.james.jspf.policies;

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

import java.util.List;

/**
 * Get the raw dns txt or spf entry which contains a spf entry. If a domain
 * publish both, and both are not equals it throws a PermError
 */
public class SPFRetrieverPolicy extends SPFRetriever {

    public SPFRetrieverPolicy(DNSService dns) {
        super(dns);
    }

    /**
     * Get the SPF-Record for a server
     * 
     * 
     * @param dns
     *            The dns service to query
     * @param hostname
     *            The hostname for which we want to retrieve the SPF-Record
     * @param spfVersion
     *            The SPF-Version which should used.
     * @return The SPF-Record if one is found.
     * @throws PermErrorException
     *             if more then one SPF-Record was found, or one SPF-Type SPF-Record 
     *             and one TXT-Type SPF-Record was published and these are not equals.
     * @throws TempErrorException
     *             if the lookup result was "TRY_AGAIN"
     */
    protected String retrieveSpfRecord(String hostname)
            throws PermErrorException, TempErrorException {

        try {
            String spfR1 = null;
            String spfR2 = null;
            // do DNS lookup for SPF-Type
            List spfR = getDNSService().getRecords(hostname, DNSService.SPF);

            // do DNS lookup for TXT-Type
            List spfTxtR = getDNSService().getRecords(hostname, DNSService.TXT);
            
            if (spfR != null) spfR1 = extractSPFRecord(spfR);
            if (spfTxtR != null) spfR2 = extractSPFRecord(spfTxtR);
            
            if (spfR1 != null && spfR2 == null) {
                return spfR1;
            } else if (spfR1 == null && spfR2 != null) {
                return spfR2;
            } else if (spfR1 != null && spfR2 != null) {
                if (spfR1.toLowerCase().equals(spfR2.toLowerCase()) == false) {
                    throw new PermErrorException("Published SPF records not equals");
                } else {
                    return spfR1;
                }
            } else {
                return null;
            }
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying dns");
        }
    }
}