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

public class ExistsMechanismn implements GenericMechanismn {

    private SPF1Data spfData;

    private String qualifier;

    private String host;

    private int maskLength;

    /**
     * @param qualifier The qualifier
     * @param host The hostname or ip 
     * @param maskLenght The maskLength
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
        List aRecords;
        
            try {
                host = new MacroExpand(spfData).expandDomain(host);

            } catch (Exception e) {
                throw new ErrorException(e.getMessage());
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
