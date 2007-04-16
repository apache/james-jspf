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

/**
 * Throws a NoneException if no record has been found
 */
public class NoSPFRecordFoundPolicy extends AbstractNestedPolicy {
    /**
     * @see org.apache.james.jspf.policies.AbstractNestedPolicy#getSPFRecordPostFilter(java.lang.String, org.apache.james.jspf.core.SPF1Record)
     */
    protected SPF1Record getSPFRecordPostFilter(String currentDomain, SPF1Record res) throws PermErrorException, TempErrorException, NoneException, NeutralException {
        if (res == null) {
            throw new NoneException("No SPF record found for host: " + currentDomain);
        } else {
            return res;
        }
    }
}