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


package org.apache.james.jspf.core;

import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

/**
 * 
 */
public class Directive {

    protected String qualifier = "+";

    private Mechanism mechanism = null;

    /**
     * Construct Directive
     * 
     * @param qualifier The qualifier to use. Valid qualifier are: +, -, ~, ?
     * @param mechanism The Mechanism 
     * @throws PermErrorException Get thrown if a PermError should returned
     */
    public Directive(String qualifier, Mechanism mechanism)
            throws PermErrorException {
        super();
        if (qualifier != null && qualifier.length() > 0) {
            this.qualifier = qualifier;
        }
        if (mechanism == null) {
            throw new PermErrorException("Mechanism cannot be null");
        }
        this.mechanism = mechanism;
    }

    /**
     * Run the Directive
     * 
     * @param spfData The SPF1Data to use
     * @return The qualifier which was returned
     * @throws PermErrorException get thrown if a PermError should returned
     * @throws TempErrorException get thrown if a TempError should returned
     * @throws NoneException get thrown if a NoneException should returned;
     */
    public String run(SPF1Data spfData) throws PermErrorException,
            TempErrorException, NoneException {
        if (mechanism.run(spfData)) {
            return qualifier;
        } else {
            return null;
        }
    }

    /**
     * Return the Mechanism which should be run
     * 
     * @return the Mechanism
     */
    public Mechanism getMechanism() {
        return mechanism;
    }

    /**
     * Return the Qualifier
     * 
     * @return the qualifier
     */
    public String getQualifier() {
        return qualifier;
    }
    
    public String toString() {
        return qualifier + mechanism;
    }

}
