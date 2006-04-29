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
import org.apache.spf.util.IPAddr;
import org.apache.spf.util.IPUtil;

import java.util.ArrayList;
import java.util.regex.MatchResult;

/**
 * This class represent the mx mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 *
 */
public class MXMechanism extends GenericMechanism {

    /**
     * ABNF: "mx"
     */
    public static final String MX_NAME_REGEX = "[mM][xX]";

    /**
     * ABNF: [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String MX_VALUE_REGEX = "(?:\\:" + SPF1Parser.DOMAIN_SPEC_REGEX + ")?"
            + "(?:" + SPF1Parser.DUAL_CIDR_LENGTH_REGEX + ")?";

    /**
     * ABNF: MX = "mx" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String MX_REGEX = MX_NAME_REGEX + MX_VALUE_REGEX;

    public MXMechanism() {
        super(MX_NAME_REGEX,MX_VALUE_REGEX);
    }

    /**
     * 
     * @see org.apache.spf.mechanismn.GenericMechanism#run(org.apache.spf.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException {
        ArrayList addressList = new ArrayList();

        // Get the right host.
        String host = expandHost(spfData);

        // get the ipAddress
        try {
            IPAddr checkAddress = IPAddr.getAddress(spfData.getIpAddress(),
                    maskLength);
            try {
                addressList.addAll(spfData.getDnsProbe().getMXRecords(host,
                        maskLength));
                if (IPUtil.checkAddressList(checkAddress, addressList)) {
                    return true;
                }
            } catch (Exception e) {
                // no a records just return null
                return false;
            }
        } catch (Exception e) {
            throw new PermErrorException("No valid ipAddress: "
                    + spfData.getIpAddress());
        }
        // No match found
        return false;
    }

    public void config(MatchResult params) throws PermErrorException {
        // TODO Auto-generated method stub
        
    }

}
