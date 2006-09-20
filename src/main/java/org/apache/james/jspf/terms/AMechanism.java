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

import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.parser.SPF1Parser;
import org.apache.james.jspf.util.Inet6Util;
import org.apache.james.jspf.util.ConfigurationMatch;

import java.util.ArrayList;
import java.util.List;

/**
 * This class represent the a mechanism
 * 
 */
public class AMechanism extends GenericMechanism {

    /**
     * ABNF: A = "a" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String REGEX = "[aA]" + "(?:\\:"
            + SPF1Parser.DOMAIN_SPEC_REGEX + ")?" + "(?:"
            + DUAL_CIDR_LENGTH_REGEX + ")?";

    private int ip4cidr;

    private int ip6cidr;

    /**
     * 
     * @see org.apache.james.jspf.core.GenericMechanism#run(org.apache.james.jspf.core.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException,
            TempErrorException {
        ArrayList addressList = new ArrayList();

        // update currentDepth
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

        // Get the right host.
        String host = expandHost(spfData);

        // get the ipAddress
        try {
            if (Inet6Util.isValidIPV4Address(spfData.getIpAddress())) {

                IPAddr checkAddress = IPAddr.getAddress(spfData.getIpAddress(),
                        getIp4cidr());

                try {
                    List aRecords =spfData.getDnsProbe().getARecords(host,getIp4cidr());
         
                    if (aRecords != null) {
                        addressList.addAll(aRecords);
                    } else {
                        return false;
                    }


                    // We should match if any A Record was found!
                    if (addressList.size() > 0 && spfData.matchAnyARecord()) return true;
                    
                    if (checkAddressList(checkAddress, addressList)) {
                        return true;
                    }
                } catch (NoneException e) {
                    e.printStackTrace();
                    // no a records just return null
                    return false;
                }
            } else {
                IPAddr checkAddress = IPAddr.getAddress(spfData.getIpAddress(),
                        getIp6cidr());

                try {
                    List aaaaRecords =spfData.getDnsProbe().getAAAARecords(host, getIp6cidr());
                    
                    if (aaaaRecords != null) {
                        addressList.addAll(aaaaRecords);
                    } else {
                        return false;
                    }

                    // We should match if any A Record was found!
                    if (addressList.size() > 0 && spfData.matchAnyAAAARecord()) return true;
                    
                    
                    if (checkAddressList(checkAddress, addressList)) {
                        return true;
                    }
                } catch (NoneException e) {
                    // no aaaa records just return null
                    return false;
                }

            }
        } catch (Exception e) {
            throw new PermErrorException("No valid ipAddress: "
                    + spfData.getIpAddress());
        }
        // No match found
        return false;
    }

    /**
     * @see org.apache.james.jspf.terms.GenericMechanism#config(ConfigurationMatch)
     */
    public synchronized void config(ConfigurationMatch params) throws PermErrorException {
        super.config(params);
        if (params.groupCount() >= 2 && params.group(2) != null) {
            ip4cidr = Integer.parseInt(params.group(2).toString());
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
    public boolean checkAddressList(IPAddr checkAddress, List addressList) throws PermErrorException {

        IPAddr aValue = null;
        for (int i = 0; i < addressList.size(); i++) {
            Object ip = addressList.get(i);

            // Check for empty record
            if (ip != null) {
                aValue = (IPAddr.getAddress(ip.toString()));
            
                if (checkAddress.getMaskedIPAddress().equals(
                        aValue.getMaskedIPAddress()) || checkAddress.toString().equals(ip.toString()) ) {
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

}
