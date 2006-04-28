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

import org.apache.spf.ErrorException;
import org.apache.spf.SPF1Data;

/**
 * This Interface represent a gerneric mechanismn 
 * @author maurer
 *
 */
public interface GenericMechanismn {
    
    /**
     * Run the mechanismn  with the give SPF1Data
     * @param spfData The SPF1Data
     * @return result If the not match it return null. Otherwise it returns the modifier
     * @throws ErrorException if somethink strange happen
     */
    public String run(SPF1Data spfData) throws ErrorException;
    
}
