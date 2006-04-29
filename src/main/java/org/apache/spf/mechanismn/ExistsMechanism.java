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
import org.apache.spf.MacroExpand;
import org.apache.spf.SPF1Data;

import java.util.List;

public class ExistsMechanism extends GenericMechanism {

    /**
     * 
     * @see org.apache.spf.mechanismn.GenericMechanism#run(org.apache.spf.SPF1Data)
     */
    public String run(SPF1Data spfData) throws PermErrorException {
        List aRecords;
        
        String host = this.host;
        try {
            host = new MacroExpand(spfData).expandDomain(host);
        } catch (Exception e) {
            throw new PermErrorException(e.getMessage());
        }

        try {
            aRecords = spfData.getDnsProbe().getARecords(host, maskLength);
        } catch (Exception e) {
            return null;
        }
        if (aRecords.size() > 0) {
            return qualifier;
        }

        // No match found
        return null;
    }

}
