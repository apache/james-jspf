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


package org.apache.james.jspf.terms;

import org.apache.james.jspf.core.Configurable;
import org.apache.james.jspf.core.Configuration;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.Mechanism;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.wiring.LogEnabled;

/**
 * This abstract class represent a gerneric mechanism
 *  
 */
public abstract class GenericMechanism implements Mechanism, Configurable, LogEnabled {

    /**
     * ABNF: ip4-cidr-length = "/" 1*DIGIT
     */
    protected static final String IP4_CIDR_LENGTH_REGEX = "/(\\d+)";

    /**
     * ABNF: ip6-cidr-length = "/" 1*DIGIT
     */
    protected static final String IP6_CIDR_LENGTH_REGEX = "/(\\d+)";

    /**
     * ABNF: dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
     */
    protected static final String DUAL_CIDR_LENGTH_REGEX = "(?:"
            + IP4_CIDR_LENGTH_REGEX + ")?" + "(?:/" + IP6_CIDR_LENGTH_REGEX
            + ")?";

    private String domain;

    protected Logger log;

    /**
     * Expand the hostname
     * 
     * @param spfData The SPF1Data to use
     * @throws PermErrorException get Thrown if invalid macros are used
     */
    protected String expandHost(SPF1Data spfData) throws PermErrorException {
        String host = getDomain();
        if (host == null) {
            host = spfData.getCurrentDomain();
        } else {
            // throws a PermErrorException that we cat pass through
            host = new MacroExpand(log).expand(host, spfData, MacroExpand.DOMAIN);
        }
        return host;
    }

    /**
     * @see org.apache.james.jspf.core.Configurable#config(Configuration)
     */
    public synchronized void config(Configuration params) throws PermErrorException {
        if (params.groupCount() >= 1 && params.group(1) != null) {
            domain = params.group(1);
        } else {
            domain = null;
        }
    }

    /**
     * @return Returns the domain.
     */
    protected synchronized String getDomain() {
        return domain;
    }

    /**
     * @see org.apache.james.jspf.wiring.LogEnabled#enableLogging(org.apache.james.jspf.core.Logger)
     */
    public void enableLogging(Logger logger) {
        this.log = logger;
    }

}
