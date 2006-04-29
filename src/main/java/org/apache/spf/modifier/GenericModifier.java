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

import org.apache.spf.PermErrorException;
import org.apache.spf.MacroExpand;
import org.apache.spf.SPF1Data;

/**
 * This class represent a gerneric modifier
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public abstract class GenericModifier {

    protected String host;

    /**
     * @param host
     *            The hostname or ip
     */
    public void init(String host) {
        this.host = host;
    }

    /**
     * @param spfData
     * @throws PermErrorException
     */
    protected String expandHost(SPF1Data spfData) throws PermErrorException {
        String host = this.host;
        if (host == null) {
            host = spfData.getCurrentDomain();
        } else {
            try {
                host = new MacroExpand(spfData).expandDomain(host);

            } catch (Exception e) {
                throw new PermErrorException(e.getMessage());
            }
        }
        return host;
    }

    /**
     * Run the mechanismn with the give SPF1Data
     * 
     * @param spfData
     *            The SPF1Data
     * @return result If the not match it return null. Otherwise it returns the
     *         modifier
     * @throws PermErrorException
     *             if somethink strange happen
     */
    public abstract String run(SPF1Data spfData) throws PermErrorException;

}
