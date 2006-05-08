/***********************************************************************
 * Copyright (c) 2006 The Apache Software Foundation.             *
 * All rights reserved.                                                *
 * ------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License"); you *
 * may not use this file except in compliance with the License. You    *
 * may obtain a copy of the License at:                                *
 *                                                                     *
 *     http://www.apache.org/licenses/LICENSE-2.0                      *
 *                                                                     *
 * Unless required by applicable law or agreed to in writing, software *
 * distributed under the License is distributed on an "AS IS" BASIS,   *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or     *
 * implied.  See the License for the specific language governing       *
 * permissions and limitations under the License.                      *
 ***********************************************************************/

package org.apache.james.jspf.core;

import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

import java.util.List;

/**
 * Interface which should be used to access all necassary DNS-Records
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 * 
 */
public interface DNSService {

    /**
     * Get the SPF-Record for a server given it's version
     * 
     * TODO: support SPF Records too. This will be done if dnsjava support it!
     * 
     * @param hostname
     *            The hostname for which we want to retrieve the SPF-Record
     * @param spfVersion
     *            The SPF-Version which should used.
     * @return The SPF-Record if one is found.
     * @throws PermErrorException
     *             if more then one SPF-Record was found.
     * @throws NoneException
     *             if no SPF-Record was found.
     * @throws TempErrorException
     *             if the lookup result was not "HOST NOT FOUND" or
     *             "SUCCESSFULLY"
     */
    public String getSpfRecord(String hostname, String spfVersion)
            throws PermErrorException, NoneException, TempErrorException;

    /**
     * Get a list of IPAddr's for a server using the mask length
     * 
     * @param strServer
     *            The hostname or ipAddress whe should get the A-Records for
     * @param mask
     *            The netmask to use
     * @return The ipAddresses
     * @throws NoneException
     *             if no A records was found
     * @throws PermErrorException
     *             if an PermError should be returned
     * @throws TempErrorException
     *             if the lookup result was not "HOST NOT FOUND" or
     *             "SUCCESSFULLY"
     */
    public List getARecords(String strServer, int mask) throws NoneException,
            PermErrorException, TempErrorException;

    /**
     * Get a list of IPAddr's for a server using the mask length
     * 
     * @param strServer
     *            The hostname or ipAddress whe should get the AAAA-Records for
     * @param mask
     *            The netmask to use
     * @return The ipAddresses
     * @throws NoneException
     *             if no AAAA records was found
     * @throws PermErrorException
     *             if an PermError should be returned
     * @throws TempErrorException
     *             if the lookup result was not "HOST NOT FOUND" or
     *             "SUCCESSFULLY"
     */
    public List getAAAARecords(String strServer, int mask)
            throws NoneException, PermErrorException, TempErrorException;

    /**
     * Get TXT records as a string
     * 
     * @param strServer
     *            The hostname for which we want to retrieve the TXT-Record
     * @return String which reflect the TXT-Record
     * @throws NoneException
     *             if no TXT-Record was found
     * @throws PermErrorException
     *             if the hostname is not resolvable
     * @throws TempErrorException
     *             if the lookup result was not "HOST NOT FOUND" or
     *             "SUCCESSFULLY"
     */
    public String getTxtCatType(String strServer) throws NoneException,
            PermErrorException, TempErrorException;

    /**
     * Get reverse DNS records
     * 
     * @param ipAddress
     *            The ipAddress for which we want to get the PTR-Record
     * @return the PTR-Records
     * @throws NoneException
     *             if no PTR-Record was found
     * @throws PermErrorException
     *             if an PermError should be returned
     * @throws TempErrorException
     *             if the lookup result was not "HOST NOT FOUND" or
     *             "SUCCESSFULLY"
     */

    public List getPTRRecords(String ipAddress) throws PermErrorException,
            NoneException, TempErrorException;

    /**
     * Get a list of masked IPAddr MX-Records
     * 
     * @param domainName
     *            The domainName or ipaddress we want to get the ips for
     * @param mask
     *            The netmask
     * @return IPAddresses of the MX-Records
     * @throws NoneException
     *             if no MX-Record was found
     * @throws PermErrorException
     *             if an PermError should be returned
     * @throws TempErrorException
     *             if the lookup result was not "HOST NOT FOUND" or
     *             "SUCCESSFULLY"
     */
    public List getMXRecords(String domainName, int mask)
            throws PermErrorException, NoneException, TempErrorException;

    /**
     * Try to get all domain names for the running host
     * 
     * @return names A List contains all domain names which could resolved
     */
    public List getLocalDomainNames();

    /**
     * Set the timeout for DNS-Requests
     * 
     * @param timeOut
     *            The timeout in seconds
     */
    public void setTimeOut(int timeOut);
}