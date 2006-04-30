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

import org.apache.spf.MacroExpand;
import org.apache.spf.PermErrorException;
import org.apache.spf.SPF1Data;

import java.util.regex.MatchResult;

/**
 * This class represent a gerneric mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public abstract class GenericMechanism implements Mechanism {

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

    protected String domain;

    /**
     * Expand the hostname
     * 
     * @param spfData
     * @throws PermErrorException
     */
    protected String expandHost(SPF1Data spfData) throws PermErrorException {
        String host = this.domain;
        if (host == null) {
            host = spfData.getCurrentDomain();
        } else {
            try {
                host = new MacroExpand(spfData).expandDomain(host);

            } catch (Exception e) {
                throw new PermErrorException(e.getMessage());
            }
        }
        return host;
    }

    public void config(MatchResult params) throws PermErrorException {
        if (params.groupCount() >= 1 && params.group(1) != null) {
            domain = params.group(1);
        } else {
            domain = null;
        }
    }

}
