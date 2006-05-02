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

package org.apache.james.jspf.terms;

import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.parser.SPF1Parser;
import org.apache.james.jspf.util.IPAddr;

import java.util.ArrayList;

/**
 * This class represent the mx mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public class MXMechanism extends AMechanism {

    /**
     * ABNF: MX = "mx" [ ":" domain-spec ] [ dual-cidr-length ]
     */
    public static final String REGEX = "[mM][xX]" + "(?:\\:"
            + SPF1Parser.DOMAIN_SPEC_REGEX + ")?" + "(?:"
            + DUAL_CIDR_LENGTH_REGEX + ")?";

    /**
     * 
     * @see org.apache.james.jspf.core.GenericMechanism#run(org.apache.james.jspf.core.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException,TempErrorException {
        ArrayList addressList = new ArrayList();

        // update currentDepth
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

        // Get the right host.
        String host = expandHost(spfData);

        // get the ipAddress
        try {
            IPAddr checkAddress = IPAddr.getAddress(spfData.getIpAddress(),
                    ip4cidr);
            try {
                addressList.addAll(spfData.getDnsProbe().getMXRecords(host,
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
        } catch (Exception e) {
            throw new PermErrorException("No valid ipAddress: "
                    + spfData.getIpAddress());
        }
        // No match found
        return false;
    }

}
