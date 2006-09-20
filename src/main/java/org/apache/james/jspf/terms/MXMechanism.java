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

import java.util.ArrayList;
import java.util.List;

/**
 * This class represent the mx mechanism
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
     * @throws NoneException 
     * @see org.apache.james.jspf.core.GenericMechanism#run(org.apache.james.jspf.core.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException,
            TempErrorException{
        ArrayList addressList = new ArrayList();
        IPAddr checkAddress;

        // update currentDepth
        spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

        // Get the right host.
        String host = expandHost(spfData);

        // get the ipAddress
        checkAddress = IPAddr.getAddress(spfData.getIpAddress(), getIp4cidr());
        
        try {
            List mxRecords = spfData.getDnsProbe().getMXRecords(host,getIp4cidr());

            // should never happen. 
            if (mxRecords == null) return false;
            
            addressList.addAll(mxRecords);
          } catch (NoneException e ) {
              e.printStackTrace();
              return false;
          }
        
        try {    
            if (checkAddressList(checkAddress, addressList)) {
                return true;
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new PermErrorException("No valid ipAddress: "
                    + spfData.getIpAddress());
        }
        // No match found
        return false;
    }

}
