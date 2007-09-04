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

import org.apache.james.jspf.core.Directive;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.policies.PolicyPostFilter;
import org.apache.james.jspf.terms.IncludeMechanism;

/**
 * PolicyPostFilter which implements trusted forwared. 
 * See http://www.trusted-forwarder.org for more informations
 *
 */
public class TrustedForwarderPolicy implements PolicyPostFilter {

    /**
     * The hostname to include
     */
    public static final String TRUSTED_FORWARDER_HOST = "spf.trusted-forwarder.org";

    
    private Logger log;

    /**
     * @param spf
     */
    public TrustedForwarderPolicy(Logger log) {
        this.log = log;
    }

    /**
     * @see org.apache.james.jspf.policies.PolicyPostFilter#getSPFRecord(java.lang.String, org.apache.james.jspf.core.SPF1Record)
     */
    public SPF1Record getSPFRecord(String currentDomain, SPF1Record spfRecord) throws PermErrorException, TempErrorException, NoneException, NeutralException {
        if (spfRecord == null) return null;
        String mechanism = ((Directive) spfRecord.getDirectives().get(spfRecord.getDirectives().size())).toString();
        if (mechanism.equals("-all") || mechanism.equals("?all")) {
            log.debug("Add TrustedForwarderPolicy = include:"+TRUSTED_FORWARDER_HOST);
            try {
                IncludeMechanism trusted = new IncludeMechanism() {
                    /**
                     * Set the host to use 
                     * 
                     * @param host the host to include
                     */
                    public synchronized IncludeMechanism setHost(String host) {
                        this.host = host;
                        return this;
                    }
                }.setHost(TRUSTED_FORWARDER_HOST);
                spfRecord.getDirectives().add(spfRecord.getDirectives().size()-1, new Directive(null, trusted, log.getChildLogger("trustedforwarder")));
            } catch (PermErrorException e) {
                // will never happen
            }
        }
        return spfRecord;
    }
}