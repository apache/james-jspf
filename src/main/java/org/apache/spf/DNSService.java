/*
 * Created on 26-apr-2006
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package org.apache.spf;

import java.util.ArrayList;

public interface DNSService {

    /**
     * Get the SPF-Record for a server given it's version
     *  
     * TODO: support SPF Records too.
     * 
     * @param hostname The hostname for which we want to retrieve the SPF-Record
     * @param spfVersion The SPF-Version which should used.
     * @return The SPF-Record if one is found.
     * @throws ErrorException if more then one SPF-Record was found.
     * @throws NoneException if no SPF-Record was found.
     * @throws NeutralException if an invalid SPF-Version was specified.
     */
    public String getSpfRecord(String hostname, String spfVersion)
            throws ErrorException, NeutralException, NoneException;

    /**
     * Get a list of IPAddr's for a server using the mask length
     * 
     * @param strServer The hostname or ipAddress whe should get the A-Records for
     * @param mask The netmask to use
     * @return The ipAddresses
     * @throws NeutralException
     * @throws NoneException if no A records was found 
     * @throws ErrorException
     */
    public ArrayList getARecords(String strServer, int mask)
            throws NeutralException, NoneException, ErrorException;

    /**
     * Get TXT records as a string
     * @param strServer The hostname for which we want to retrieve the TXT-Record
     * @return String which reflect the TXT-Record
     * @throws NoneException if no TXT-Record was found 
     * @throws ErrorException if the hostname is not resolvable
     */
    public String getTxtCatType(String strServer) throws NoneException,
            ErrorException;

    /**
     * Get reverse DNS records
     * 
     * @param ipAddress The ipAddress for which we want to get the PTR-Record
     * @return the PTR-Records
     * @throws NoneException if no PTR-Record was found
     * 
     */

    public ArrayList getPTRRecords(String ipAddress) throws ErrorException,
            NoneException, NeutralException;

    /**
     * Get a list of masked IPAddr MX-Records
     *  
     * @param domainName The domainName or ipaddress we want to get the ips for
     * @param mask The netmask
     * @return IPAddresses of the MX-Records
     * @throws NoneException if no MX-Record was found
     * @throws ErrorException
     */
    public ArrayList getMXRecords(String domainName, int mask)
            throws ErrorException, NoneException;

}