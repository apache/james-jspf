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

package org.apache.james.jspf.core;

import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

/**
 * This Interface represent a modifier
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 * 
 */
public interface Modifier {

    /**
     * Run the mechanismn with the give SPF1Data
     * 
     * @param spfData
     *            The SPF1Data we should use
     * @return host The host we should redirect / include
     * @throws PermErrorException
     *             Get thrown if there are any errors in modifiers
     * @throws TempErrorException
     *             Get thrown if DNS problems detected
     */
    public String run(SPF1Data spfData) throws PermErrorException,
            TempErrorException;

    /**
     * @return true if only one instance of this modifier is allowed
     */
    public boolean enforceSingleInstance();
}
