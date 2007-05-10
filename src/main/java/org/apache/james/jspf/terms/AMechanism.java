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
import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSResponse;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.Directive;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerDNSResponseListener;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.util.Inet6Util;
import org.apache.james.jspf.util.SPFTermsRegexps;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represent the a mechanism
 * 
 */
public class AMechanism extends GenericMechanism implements SPFCheckerDNSResponseListener {

    private static final String ATTRIBUTE_AMECHANISM_IPV4CHECK = "AMechanism.ipv4check";

    /**
     * ABNF: A = "a" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String REGEX = "[aA]" + "(?:\\:"
            + SPFTermsRegexps.DOMAIN_SPEC_REGEX + ")?" + "(?:"
            + DUAL_CIDR_LENGTH_REGEX + ")?";

    private int ip4cidr;

    private int ip6cidr;

    private SPFChecker expandedChecker = new ExpandedChecker();

    private final class ExpandedChecker implements SPFChecker {
        public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
                TempErrorException, NeutralException, NoneException {
            // Get the right host.
            String host = expandHost(spfData);

            // get the ipAddress
            try {
                boolean validIPV4Address = Inet6Util.isValidIPV4Address(spfData.getIpAddress());
                spfData.setAttribute(ATTRIBUTE_AMECHANISM_IPV4CHECK, Boolean.valueOf(validIPV4Address));
                if (validIPV4Address) {

                    List aRecords = getARecords(host);
                    if (aRecords == null) {
                        try {
                            DNSRequest request = new DNSRequest(host, DNSRequest.A);
                            return new DNSLookupContinuation(request, AMechanism.this);
                        } catch (NoneException e) {
                            return onDNSResponse(new DNSResponse(aRecords), spfData);
                        }
                    } else {
                        return onDNSResponse(new DNSResponse(aRecords), spfData);
                    }
         
                } else {
                    
                    List aaaaRecords = getAAAARecords(host);
                    if (aaaaRecords == null) {
                        try {
                            DNSRequest request = new DNSRequest(host, DNSRequest.AAAA);
                            return new DNSLookupContinuation(request, AMechanism.this);
                        } catch (NoneException e) {
                            return onDNSResponse(new DNSResponse(aaaaRecords), spfData);
                        }
                    } else {
                        return onDNSResponse(new DNSResponse(aaaaRecords), spfData);
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
    }

    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException, TempErrorException, NeutralException, NoneException {
        // update currentDepth
        spfData.increaseCurrentDepth();

        spfData.pushChecker(expandedChecker);
        
        return macroExpand.checkExpand(getDomain(), spfData, MacroExpand.DOMAIN);
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
    public List getAAAARecords(String strServer) {
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
     * @param strServer
     *            The hostname or ipAddress whe should get the A-Records for
     * @return The ipAddresses
     */
    public List getARecords(String strServer) {
        List listAData = null;
        if (IPAddr.isIPAddr(strServer)) {
            listAData = new ArrayList();
            listAData.add(strServer);
        }
        return listAData;
    }

    /**
     * @see org.apache.james.jspf.core.SPFCheckerDNSResponseListener#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation onDNSResponse(DNSResponse response, SPFSession spfSession)
        throws PermErrorException, TempErrorException, NoneException, NeutralException {
        List listAData = null;
        try {
            listAData = response.getResponse();
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying dns server");
        }
        // no a records just return null
        if (listAData == null) {
            spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
            return null;
        }

        Boolean ipv4check = (Boolean) spfSession.getAttribute(ATTRIBUTE_AMECHANISM_IPV4CHECK);
        if (ipv4check.booleanValue()) {

            IPAddr checkAddress = IPAddr.getAddress(spfSession.getIpAddress(),
                    getIp4cidr());

            if (checkAddressList(checkAddress, listAData, getIp4cidr())) {
                spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.TRUE);
                return null;
            }

        } else {

            IPAddr checkAddress = IPAddr.getAddress(spfSession.getIpAddress(),
                    getIp6cidr());
            
            if (checkAddressList(checkAddress, listAData, getIp6cidr())) {
                spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.TRUE);
                return null;
            }

        }
        
        spfSession.setAttribute(Directive.ATTRIBUTE_MECHANISM_RESULT, Boolean.FALSE);
        return null;
    }

}
