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

import org.apache.james.jspf.core.Configuration;
import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSResponse;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.util.DNSResolver;
import org.apache.james.jspf.util.Inet6Util;
import org.apache.james.jspf.util.SPFTermsRegexps;
import org.apache.james.jspf.wiring.DNSServiceEnabled;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represent the a mechanism
 * 
 */
public class AMechanism extends GenericMechanism implements DNSServiceEnabled {

    private static final String ATTRIBUTE_AMECHANISM_RESULT = "AMechanism.result";

    /**
     * ABNF: A = "a" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String REGEX = "[aA]" + "(?:\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX + ")?" + "(?:"
            + DUAL_CIDR_LENGTH_REGEX + ")?";

    private int ip4cidr;

    private int ip6cidr;

    protected DNSService dnsService;

    /**
     * 
     * @throws NoneException 
     * @throws NeutralException 
     * @see org.apache.james.jspf.core.GenericMechanism#run(org.apache.james.jspf.core.SPFSession)
     */
    public boolean run(SPFSession spfData) throws PermErrorException,
            TempErrorException, NeutralException, NoneException {
        // update currentDepth
        spfData.increaseCurrentDepth();

        SPFChecker checker = new SPFChecker() {

            public void checkSPF(SPFSession spfData) throws PermErrorException,
                    TempErrorException, NeutralException, NoneException {
                // Get the right host.
                String host = expandHost(spfData);

                // get the ipAddress
                try {
                    boolean validIPV4Address = Inet6Util.isValidIPV4Address(spfData.getIpAddress());
                    spfData.setAttribute("AMechanism.ipv4check", Boolean.valueOf(validIPV4Address));
                    if (validIPV4Address) {

                        List aRecords = getARecords(dnsService,host);
                        if (aRecords == null) {
                            onDNSResponse(DNSResolver.lookup(dnsService, new DNSRequest(host, DNSService.A)), spfData);
                        } else {
                            onDNSResponse(new DNSResponse(aRecords), spfData);
                        }
             
                    } else {
                        
                        List aaaaRecords = getAAAARecords(dnsService, host);
                        if (aaaaRecords == null) {
                            onDNSResponse(DNSResolver.lookup(dnsService, new DNSRequest(host, DNSService.AAAA)), spfData);
                        } else {
                            onDNSResponse(new DNSResponse(aaaaRecords), spfData);
                        }

                    }
                // PermError / TempError
                // TODO: Should we replace this with the "right" Exceptions ?
                } catch (Exception e) {
                    log.debug("No valid ipAddress: ",e);
                    throw new PermErrorException("No valid ipAddress: "
                            + spfData.getIpAddress());
                }
                
            }
            
        };
        
        DNSResolver.hostExpand(dnsService, macroExpand, getDomain(), spfData, MacroExpand.DOMAIN, checker);
        
        Boolean res = (Boolean) spfData.getAttribute(ATTRIBUTE_AMECHANISM_RESULT);
        return res != null ? res.booleanValue() : false;
    }

    /**
     * @see org.apache.james.jspf.terms.GenericMechanism#config(Configuration)
     */
    public synchronized void config(Configuration params) throws PermErrorException {
        super.config(params);
        if (params.groupCount() >= 2 && params.group(2) != null) {
            ip4cidr = Integer.parseInt(params.group(2));
            if (ip4cidr > 32) {
                throw new PermErrorException("Ivalid IP4 CIDR length");
            }
        } else {
            ip4cidr = 32;
        }
        if (params.groupCount() >= 3 && params.group(3) != null) {
            ip6cidr = Integer.parseInt(params.group(3).toString());
            if (ip6cidr > 128) {
                throw new PermErrorException("Ivalid IP6 CIDR length");
            }
        } else {
            ip6cidr = 128;
        }
    }

    /**
     * Check if the given ipaddress array contains the provided ip.
     * 
     * @param checkAddress
     *            The ip wich should be contained in the given ArrayList
     * @param addressList
     *            The ip ArrayList.
     * @return true or false
     * @throws PermErrorException 
     */
    public boolean checkAddressList(IPAddr checkAddress, List addressList, int cidr) throws PermErrorException {

        for (int i = 0; i < addressList.size(); i++) {
            String ip = (String) addressList.get(i);

            // Check for empty record
            if (ip != null) {
                // set the mask in the address.
                // TODO should we use cidr from the parameters or the input checkAddress cidr?
                IPAddr ipAddr = IPAddr.getAddress(ip, checkAddress.getMaskLength());
                if (checkAddress.getMaskedIPAddress().equals(
                        ipAddr.getMaskedIPAddress())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @return Returns the ip4cidr.
     */
    protected synchronized int getIp4cidr() {
        return ip4cidr;
    }

    /**
     * @return Returns the ip6cidr.
     */
    protected synchronized int getIp6cidr() {
        return ip6cidr;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return toString("a");
    }

    /**
     * @see java.lang.Object#toString()
     */
    protected String toString(String mechKey) {
        StringBuffer res = new StringBuffer();
        res.append(mechKey);
        if (getDomain() != null) {
            res.append(":"+getDomain());
        }
        if (getIp4cidr() != 32) {
            res.append("/"+getIp4cidr());
        }
        if (getIp6cidr() != 128) {
            res.append("//"+getIp4cidr());
        }
        return res.toString();
    }
    
    
    /**
     * Retrieve a list of AAAA records
     */
    public List getAAAARecords(DNSService dns, String strServer)
            throws PermErrorException, TempErrorException {
        List listAAAAData = null;
        if (IPAddr.isIPV6(strServer)) {
            // Address is already an IP address, so add it to list
            listAAAAData = new ArrayList();
            listAAAAData.add(strServer);
        }
        return listAAAAData;
    }


    /**
     * Get a list of IPAddr's for a server
     * 
     * @params dns the DNSService to query
     * @param strServer
     *            The hostname or ipAddress whe should get the A-Records for
     * @return The ipAddresses
     * @throws PermErrorException
     *             if an PermError should be returned
     * @throws TempErrorException
     *             if the lookup result was "TRY_AGAIN"
     */
    public List getARecords(DNSService dns, String strServer) throws PermErrorException, TempErrorException {
        List listAData = null;
        if (IPAddr.isIPAddr(strServer)) {
            listAData = new ArrayList();
            listAData.add(strServer);
        }
        return listAData;
    }

    /**
     * @see org.apache.james.jspf.wiring.DNSServiceEnabled#enableDNSService(org.apache.james.jspf.core.DNSService)
     */
    public void enableDNSService(DNSService service) {
        this.dnsService = service;
    }


    private void onDNSResponse(DNSResponse response, SPFSession spfSession)
        throws PermErrorException, TempErrorException, NoneException {
        List listAData = null;
        try {
            listAData = response.getResponse();
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying dns server");
        }
        // no a records just return null
        if (listAData == null) {
            spfSession.setAttribute(ATTRIBUTE_AMECHANISM_RESULT, Boolean.FALSE);
            return;
        }

        Boolean ipv4check = (Boolean) spfSession.getAttribute("AMechanism.ipv4check");
        if (ipv4check.booleanValue()) {

            IPAddr checkAddress = IPAddr.getAddress(spfSession.getIpAddress(),
                    getIp4cidr());

            if (checkAddressList(checkAddress, listAData, getIp4cidr())) {
                spfSession.setAttribute(ATTRIBUTE_AMECHANISM_RESULT, Boolean.TRUE);
                return;
            }

        } else {

            IPAddr checkAddress = IPAddr.getAddress(spfSession.getIpAddress(),
                    getIp6cidr());
            
            if (checkAddressList(checkAddress, listAData, getIp6cidr())) {
                spfSession.setAttribute(ATTRIBUTE_AMECHANISM_RESULT, Boolean.TRUE);
                return;
            }

        }
        
        spfSession.setAttribute(ATTRIBUTE_AMECHANISM_RESULT, Boolean.FALSE);
        return;
    }

}
