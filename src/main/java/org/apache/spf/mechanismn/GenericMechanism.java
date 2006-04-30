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
import org.apache.spf.util.IPAddr;

import java.net.InetAddress;
import java.util.regex.MatchResult;

/**
 * This class represent a gerneric mechanism
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * 
 */
public abstract class GenericMechanism extends AbstractMechanism {
    
    protected String host;

    protected int maskLength;

    /**
     * Initialize the mechanism
     * 
     * @param qualifier
     *            The mechanismPrefix
     * @param host
     *            The hostname or ip
     * @param maskLenght
     *            The maskLength
     */
    public void init(String host, int maskLength) {
        this.host = host;
        this.maskLength = maskLength;
    }

    public GenericMechanism(String name, String value) {
        super(name,value);
    }
    
    /**
     * Expand the hostname
     * 
     * @param spfData
     * @throws PermErrorException
     */
    protected String expandHost(SPF1Data spfData) throws PermErrorException {
        String host = this.host;
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
            host = params.group(1);
            IPAddr.getInAddress(host);
        } else {
            host = null;
        }
        if (params.groupCount() >= 2 && params.group(2) != null) {
            maskLength = Integer.parseInt(params.group(2).toString());
        } else {
            maskLength = 32;
        }
        if (params.groupCount() >= 3 && params.group(3) != null) {
            maskLength = Integer.parseInt(params.group(3).toString());
        } else {
            maskLength = getLength();
        }
    }
    
    protected int getLength() {
        return 128;
    }

}
