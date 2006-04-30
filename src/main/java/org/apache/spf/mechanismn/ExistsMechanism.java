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

import org.apache.spf.MacroExpand;
import org.apache.spf.PermErrorException;
import org.apache.spf.SPF1Data;
import org.apache.spf.SPF1Parser;

import java.util.List;

/**
 * This class represent the exists mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 *
 */
public class ExistsMechanism extends GenericMechanism {

    /**
     * ABNF: "exists"
     */
    public static final String EXISTS_NAME_REGEX = "[eE][xX][iI][sS][tT][sS]";
    
    /**
     * ABNF: "exists" ":" domain-spec
     */
    public static final String EXISTS_VALUE_REGEX = "\\:" + SPF1Parser.DOMAIN_SPEC_REGEX;
    
    /**
     * ABNF: exists = "exists" ":" domain-spec
     */
    public static final String EXISTS_REGEX = EXISTS_NAME_REGEX + EXISTS_VALUE_REGEX;
    
    public ExistsMechanism() {
        super(EXISTS_NAME_REGEX,EXISTS_VALUE_REGEX);
    }

    /**
     * 
     * @see org.apache.spf.mechanismn.GenericMechanism#run(org.apache.spf.SPF1Data)
     */
    public boolean run(SPF1Data spfData) throws PermErrorException {
        List aRecords;

        String host = expandHost(spfData);
        try {
            host = new MacroExpand(spfData).expandDomain(host);
        } catch (Exception e) {
            throw new PermErrorException(e.getMessage());
        }

        try {
            // TODO: is 32 the correct default?
            aRecords = spfData.getDnsProbe().getARecords(host, 32);
        } catch (Exception e) {
            return false;
        }
        if (aRecords.size() > 0) {
            return true;
        }

        // No match found
        return false;
    }

}
