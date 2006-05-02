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

package org.apache.james.jspf.modifier;

import org.apache.james.jspf.Configurable;
import org.apache.james.jspf.MacroExpand;
import org.apache.james.jspf.PermErrorException;
import org.apache.james.jspf.SPF1Data;
import org.apache.james.jspf.TempErrorException;

import java.util.regex.MatchResult;

/**
 * This class represent a gerneric modifier
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public abstract class GenericModifier implements Modifier, Configurable {

    protected String host;

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
     * @throws TempErrorException 
     */
    public abstract String run(SPF1Data spfData) throws PermErrorException, TempErrorException;

    public void config(MatchResult params) throws PermErrorException {
        if (params.groupCount() > 0) {
            this.host = params.group(1);
        }
    }

}
