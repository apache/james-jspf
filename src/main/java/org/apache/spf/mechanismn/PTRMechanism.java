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

import java.util.ArrayList;
import java.util.List;

/**
 * This class represent the ptr mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public class PTRMechanism extends GenericMechanism {

    /**
     * ABNF: PTR = "ptr" [ ":" domain-spec ]
     */
    public static final String REGEX = "[pP][tT][rR]" + "(?:\\:"
            + SPF1Parser.DOMAIN_SPEC_REGEX + ")?";

    /**
     * 
     * @see org.apache.spf.mechanismn.GenericMechanism#run(org.apache.spf.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException,TempErrorException {
        String compareDomain;
        IPAddr compareIP;
        ArrayList validatedHosts = new ArrayList();

        // update currentDepth
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

        // Get the right host.
        String host = expandHost(spfData);

        try {
            // Get PTR Records for the ipAddress which is provided by SPF1Data
            List domainList = spfData.getDnsProbe().getPTRRecords(
                    spfData.getIpAddress());
            for (int i = 0; i < domainList.size(); i++) {

                // Get a record for this
                // TODO with no maskLength what should we get?
                List aList = spfData.getDnsProbe().getARecords(
                        (String) domainList.get(i), 32);
                for (int j = 0; j < aList.size(); j++) {
                    compareIP = (IPAddr) aList.get(j);
                    if (compareIP.toString().equals(spfData.getIpAddress())) {
                        validatedHosts.add(domainList.get(i));
                    }
                }
            }

            // Check if we match one of this ptr!
            for (int j = 0; j < validatedHosts.size(); j++) {
                compareDomain = (String) validatedHosts.get(j);
                if (compareDomain.equals(host)
                        || compareDomain.endsWith("." + host)) {
                    return true;
                }
            }
        } catch (TempErrorException e) {
            throw new TempErrorException(e.getMessage());
        } catch (Exception e) {
            // TODO what exceptions do we want to catch with this?
            return false;
        }

        return false;

    }

}
