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

package org.apache.spf.modifier;

import org.apache.spf.MacroExpand;
import org.apache.spf.PermErrorException;
import org.apache.spf.SPF1Data;

/**
 * This class represent the redirect modifier
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public class RedirectModifier extends GenericModifier {

    /**
     * Set the host which should be used for redirection and set it in SPF1Data
     * so it can be accessed easy later if needed
     * 
     * @param spfData
     *            The SPF1Data which should used
     * @return host The host to which we shuld redirect
     * @throws PermErrorException
     *             if an error is in the redirect modifier
     */
    public String run(SPF1Data spfData) throws PermErrorException {
        String host = this.host;
        try {
            host = new MacroExpand(spfData).expandDomain(host);
            return host;
        } catch (Exception e) {
            throw new PermErrorException("Error in redirect modifier: " + host);
        }
    }

}
