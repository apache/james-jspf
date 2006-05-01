/***********************************************************************
 * Copyright (c) 1999-2006 The Apache Software Foundation.             *
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

package org.apache.spf.mechanismn;

import org.apache.spf.PermErrorException;
import org.apache.spf.SPF1Data;
import org.apache.spf.SPF1Parser;
import org.apache.spf.TempErrorException;
import org.apache.spf.util.IPAddr;
import org.apache.spf.util.Inet6Util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.MatchResult;

/**
 * This class represent the a mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 */
public class AMechanism extends GenericMechanism {

    /**
     * ABNF: A = "a" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String REGEX = "[aA]" + "(?:\\:"
            + SPF1Parser.DOMAIN_SPEC_REGEX + ")?" + "(?:"
            + DUAL_CIDR_LENGTH_REGEX + ")?";

    protected int ip4cidr;

    protected int ip6cidr;

    /**
     * 
     * @see org.apache.spf.mechanismn.GenericMechanism#run(org.apache.spf.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException,TempErrorException {
        ArrayList addressList = new ArrayList();
        
        // update currentDepth
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

        // Get the right host.
        String host = expandHost(spfData);

        // get the ipAddress
        try {
            if(Inet6Util.isValidIPV4Address(spfData.getIpAddress())) {
            
                IPAddr checkAddress = IPAddr.getAddress(spfData.getIpAddress(),
                    ip4cidr);
            
                try {
                    addressList.addAll(spfData.getDnsProbe().getARecords(host,
                        ip4cidr));
                    if (checkAddressList(checkAddress, addressList)) {
                        return true;
                    }
                } catch (TempErrorException e) {
                    throw new TempErrorException(e.getMessage());
                } catch (Exception e) {
                    // no a records just return null
                    return false;
                }
            } else {
                IPAddr checkAddress = IPAddr.getAddress(spfData.getIpAddress(),
                        ip6cidr);
                
                    try {
                        addressList.addAll(spfData.getDnsProbe().getAAAARecords(host,
                            ip6cidr));
                        if (checkAddressList(checkAddress, addressList)) {
                            return true;
                        }
                    } catch (TempErrorException e) {
                        throw new TempErrorException(e.getMessage());
                    } catch (Exception e) {
                        // no a records just return null
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

    public void config(MatchResult params) throws PermErrorException {
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
     */
    public boolean checkAddressList(IPAddr checkAddress, List addressList) {

        IPAddr aValue = null;
        for (int i = 0; i < addressList.size(); i++) {

            aValue = (IPAddr) addressList.get(i);

            if (checkAddress.getMaskedIPAddress().equals(
                    aValue.getMaskedIPAddress())) {
                return true;
            }
        }
        return false;
    }

}
