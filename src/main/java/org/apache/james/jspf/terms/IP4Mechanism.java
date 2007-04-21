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
import org.apache.james.jspf.core.DNSResponse;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.util.Inet6Util;

/**
 * This class represent the ip4 mechanism
 * 
 */
public class IP4Mechanism extends GenericMechanism {

    /**
     * ABNF: IP4 = "ip4" ":" ip4-network [ ip4-cidr-length ]
     */
    public static final String REGEX = "[iI][pP][4]" + "\\:" + "([0-9.]+)"
            + "(?:" + IP4_CIDR_LENGTH_REGEX + ")?";

    private IPAddr ip = null;

    /**
     * 
     * @see org.apache.james.jspf.core.GenericMechanism#run(org.apache.james.jspf.core.SPFSession)
     */
    public boolean run(SPFSession spfData) throws PermErrorException {
        IPAddr originalIP;

        originalIP = IPAddr.getAddress(spfData.getIpAddress(), getIp()
                .getMaskLength());

        if (getIp().getMaskedIPAddress().equals(originalIP.getMaskedIPAddress())) {
            return true;
        } else {
            // No match
            return false;
        }
    }

    /**
     * @see org.apache.james.jspf.terms.GenericMechanism#config(Configuration)
     */
    public synchronized void config(Configuration params) throws PermErrorException {
        if (params.groupCount() == 0) {
            throw new PermErrorException("Missing ip");
        }
        String ipString = params.group(1);
        if (!isValidAddress(ipString)) {
            throw new PermErrorException("Invalid Address: " + ipString);
        }
        int maskLength = getMaxCidr();
        if (params.groupCount() >= 2 && params.group(2) != null) {
            String maskLengthString = params.group(2);
            maskLength = Integer.parseInt(maskLengthString);

            if (maskLength > getMaxCidr() || (maskLengthString.length() > 1 && maskLengthString.startsWith("0"))) {
                throw new PermErrorException("Invalid CIDR: " + maskLengthString);
            }
        }
        ip = IPAddr.getAddress(ipString, maskLength);
    }

    /**
     * @see org.apache.james.jspf.util.Inet6Util#isValidIPV4Address(String)
     */
    protected boolean isValidAddress(String ipString) {
        return Inet6Util.isValidIPV4Address(ipString);
    }

    /**
     * Returns the max cidr for ip4
     * 
     * @return maxCidr The max cidr
     */
    protected int getMaxCidr() {
        return 32;
    }

    /**
     * @return Returns the ip.
     */
    protected synchronized IPAddr getIp() {
        return ip;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        if (getIp().getMaskLength() == getMaxCidr()) {
            return "ip4:"+getIp().getIPAddress();
        } else {
            return "ip4:"+getIp().getIPAddress()+"/"+getIp().getMaskLength();
        }
    }

    /**
     * @see org.apache.james.jspf.core.Mechanism#onDNSResponse(org.apache.james.jspf.core.DNSResponse, org.apache.james.jspf.core.SPFSession)
     */
    public boolean onDNSResponse(DNSResponse response, SPFSession spfSession)
            throws PermErrorException, TempErrorException, NoneException {
        // not needed, IP4Mechanism does not require further lookups
        return false;
    }
}
