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



package org.apache.james.jspf.localpolicy;

import java.util.ArrayList;
import java.util.Collection;

import org.apache.james.jspf.core.Directive;
import org.apache.james.jspf.core.Mechanism;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.terms.IncludeMechanism;
import org.apache.james.jspf.core.Logger;

/**
 * 
 * This class represent a local policy to support the whitelist of trusted-forwarder.org
 */
public class TrustedForwarderPolicy {

    /**
     * The hostname to include
     */
    private static final String TRUSTED_FORWARDER_HOST = "spf.trusted-forwarder.org";
    
    /**
     * The ArrayList whill holds the Directives to return
     */
    private ArrayList aCom;
    
    /**
     * The logger
     */
    private Logger log;
    
    /**
     * Default Constructor 
     * 
     * @param directives the Collection which holds all directives
     * @parm log the logger the logger
     * @throws IllegalArgumentException get thrown if the given Collection is null
     */
    public TrustedForwarderPolicy (Collection directives,Logger log)throws IllegalArgumentException {
        if (directives == null) throw new IllegalArgumentException("Passed Collection is null");
        this.aCom = new ArrayList(directives);
        this.log = log;
    }

    /**
     * Return an updated Collection which hold now a new include mechanism to quere trusted-forwarder.org. The
     * Collection get only updated if the last mechanism is -all or ?all. If not the original Collection is returned
     * 
     * @return aCom a Collection which holds the directives
     */
    public Collection getUpdatedDirectives() {
        String mechanism = ((Directive) aCom.get(aCom.size())).toString().toLowerCase();
        if (mechanism.equals("-all") || mechanism.equals("?all")) {
            log.debug("Add TrustedForwarderPolicy = include:"+TRUSTED_FORWARDER_HOST);
            try {
                Mechanism trusted = new IncludeMechanism() {
                    /**
                     * Set the host to use 
                     * 
                     * @param host the host to include
                     */
                    public Mechanism setHost(String host) {
                        this.host = host;
                        return this;
                    }
                }.setHost(TRUSTED_FORWARDER_HOST);
                aCom.add(aCom.size()-1, new Directive(null,trusted));
            } catch (PermErrorException e) {
                // will never happen
            }
            return aCom;
        } else {
            return aCom;
        }
    }
}
