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


package org.apache.james.jspf;

import org.apache.james.jspf.core.SPF1Constants;

/**
 * This class is used to return the result of an SPF lookup.
 *
 */

public class SPFInternalResult {

    protected String explanation = null;
    
    private String resultChar = null;

    public SPFInternalResult(String resultChar, String explanation) {
        this.resultChar = resultChar;
        this.explanation = explanation;
    }

    /**
     * Get the explanation. The explanation is only set if the result is "-" =
     * fail
     * 
     * @return explanation
     */
    public String getExplanation() {
        return explanation;
    }
    
    /**
     * Get the result char "+-~?"
     * 
     * @see SPF1Constants
     * @return resultchar
     */
    public String getResultChar() {
        return resultChar != null ? resultChar : "";
    }

}
