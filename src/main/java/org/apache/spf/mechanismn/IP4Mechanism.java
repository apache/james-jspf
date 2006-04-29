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
     * ABNF: ip4-cidr-length = "/" 1*DIGIT
     */
    static public final String IP4_CIDR_LENGTH_REGEX = "/(\\d+)";

    /**
     * TODO ABNF: ip4-network [ ip4-cidr-length ]
     */
    public static final String IP4_VALUE_REGEX = "\\:" + "([0-9.]+)" + "(?:" + IP4_CIDR_LENGTH_REGEX + ")?";

    /**
     * TODO ABNF: IP4 = "ip4" ":" ip4-network [ ip4-cidr-length ]
     */
    public static final String IP4_REGEX = IP4_NAME_REGEX + IP4_VALUE_REGEX;
    
    public IP4Mechanism() {
        super(IP4_NAME_REGEX,IP4_VALUE_REGEX);
    }

    /**
     * 
     * @see org.apache.spf.mechanismn.GenericMechanism#run(org.apache.spf.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException {
        IPAddr testIP;
        IPAddr originalIP;

        if (Inet6Util.isValidIPV4Address(host) == false) {
            throw new PermErrorException("Not a valid IP address: " + host);
        }

        testIP = IPAddr.getAddress(host, maskLength);
        originalIP = IPAddr.getAddress(spfData.getIpAddress(), 32);

        if (testIP.getMaskedIPAddress().equals(originalIP.getMaskedIPAddress())) {
            return true;
        } else {
            // No match
            return false;
        }
    }

    public int getLength() {
        return 32;
    }

}
