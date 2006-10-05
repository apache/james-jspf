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

package org.apache.james.jspf.policies;

import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

import java.util.Iterator;
import java.util.List;

/**
 * Composed policy: get a list of NestedPolicies and chain them
 * in a single policy
 */
public class ChainPolicy implements Policy {
    
    private Policy policy;

    /**
     * Create a new ChainPolicy
     * @param policies an array of Polcy and NestedPolicy objects
     */
    public ChainPolicy(List policies) {
        policy = null;
        Iterator i = policies.iterator();
        while (i.hasNext()) {
            Policy newP = (Policy) i.next();
            if (newP instanceof NestedPolicy) {
                ((NestedPolicy) newP).setChildPolicy(policy);
            }
            policy = newP;
        }
    }
    
    /**
     * @see org.apache.james.jspf.policies.Policy#getSPFRecord(java.lang.String)
     */
    public SPF1Record getSPFRecord(String currentDomain)
            throws PermErrorException, TempErrorException, NoneException,
            NeutralException {
        return policy.getSPFRecord(currentDomain);
    }

}
