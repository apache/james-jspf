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

import java.util.ArrayList;
import java.util.List;

import org.apache.spf.ErrorException;
import org.apache.spf.MacroExpand;
import org.apache.spf.SPF1Data;
import org.apache.spf.util.IPAddr;

public class PTRMechanismn implements GenericMechanismn {

    private SPF1Data spfData;

    private String qualifier;

    private String host;

    private int maskLength;

    /**
     * @param qualifier
     *            The qualifier
     * @param host
     *            The hostname or ip
     * @param maskLenght
     *            The maskLength
     */
    public void init(String qualifier, String host, int maskLength) {

        this.qualifier = qualifier;
        this.host = host;
        this.maskLength = maskLength;
    }

    /**
     * 
     * @see org.apache.spf.mechanismn.GenericMechanismn#run(org.apache.spf.SPF1Data)
     */
    public String run(SPF1Data spfData) throws ErrorException {
        this.spfData = spfData;

        String compareDomain;
        IPAddr compareIP;
        ArrayList validatedHosts = new ArrayList();

        // Get the right host.
        if (host == null) {
            host = spfData.getCurrentDomain();
        } else {
            try {
                host = new MacroExpand(spfData).expandDomain(host);
            } catch (Exception e) {
                throw new ErrorException(e.getMessage());
            }
        }
        try {
            // Get PTR Records for the ipAddress which is provided by SPF1Data
            List domainList = spfData.getDnsProbe().getPTRRecords(
                    spfData.getIpAddress());
            for (int i = 0; i < domainList.size(); i++) {
                
                // Get a record for this
                List aList = spfData.getDnsProbe().getARecords(
                        (String) domainList.get(i), maskLength);
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
                    return qualifier;
                }
            }
        } catch (Exception e) {
            return null;
        }

        return null;

    }

}
