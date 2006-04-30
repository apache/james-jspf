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
import org.apache.spf.util.IPAddr;
import org.apache.spf.util.Inet6Util;

import java.util.regex.MatchResult;

/**
 * This class represent the ip4 mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public class IP4Mechanism extends GenericMechanism {

    /**
     * ABNF: "ip4"
     */
    public static final String IP4_NAME_REGEX = "[iI][pP][4]";

    /**
     * TODO ABNF: ip4-network [ ip4-cidr-length ]
     */
    public static final String IP4_VALUE_REGEX = "\\:" + "([0-9.]+)" + "(?:"
            + IP4_CIDR_LENGTH_REGEX + ")?";

    /**
     * TODO ABNF: IP4 = "ip4" ":" ip4-network [ ip4-cidr-length ]
     */
    public static final String IP4_REGEX = IP4_NAME_REGEX + IP4_VALUE_REGEX;

    public IP4Mechanism() {
        this(IP4_NAME_REGEX, IP4_VALUE_REGEX);
    }

    public IP4Mechanism(String namePattern, String valuePattern) {
        super(namePattern, valuePattern);
    }

    private IPAddr ip = null;

    private int maskLength = 0;

    /**
     * 
     * @see org.apache.spf.mechanismn.GenericMechanism#run(org.apache.spf.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException {
        IPAddr originalIP;

        originalIP = IPAddr.getAddress(spfData.getIpAddress(), 32);

        if (ip.getMaskedIPAddress().equals(originalIP.getMaskedIPAddress())) {
            return true;
        } else {
            // No match
            return false;
        }
    }

    public void config(MatchResult params) throws PermErrorException {
        if (params.groupCount() == 0) {
            throw new PermErrorException("Missing ip");
        }
        String ipString = params.group(1);
        if (!isValidAddress(ipString)) {
            throw new PermErrorException("Invalid Address");
        }
        maskLength = getMaxCidr();
        if (params.groupCount() >= 2 && params.group(2) != null) {
            maskLength = Integer.parseInt(params.group(2).toString());
            if (maskLength > getMaxCidr()) {
                throw new PermErrorException("Invalid CIDR");
            }
        }
        ip = IPAddr.getAddress(ipString, maskLength);
    }

    protected boolean isValidAddress(String ipString) {
        return Inet6Util.isValidIPV4Address(ipString);
    }

    protected int getMaxCidr() {
        return 32;
    }

}
