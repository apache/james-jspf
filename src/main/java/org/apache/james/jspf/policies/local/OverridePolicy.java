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

package org.apache.james.jspf.policies.local;

import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

public class OverridePolicy extends FallbackPolicy {

    public OverridePolicy(Logger log, SPFRecordParser parser) {
        super(log, parser);
    }
    

    /**
     * @see org.apache.james.jspf.policies.AbstractNestedPolicy#getSPFRecordPostFilter(java.lang.String, org.apache.james.jspf.core.SPF1Record)
     */
    protected SPF1Record getSPFRecordPostFilter(String currentDomain, SPF1Record res) throws PermErrorException, TempErrorException, NoneException, NeutralException {
        return res;
    }

    /**
     * @see org.apache.james.jspf.policies.AbstractNestedPolicy#getSPFRecordOverride(java.lang.String)
     */
    public SPF1Record getSPFRecordOverride(String host) {
        return getMySPFRecord(host);
    }

}
