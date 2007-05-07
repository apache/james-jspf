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
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;

public final class DNSRequest {

    /** The record types for the lookups */
    public static final int A = 1;
    public static final int AAAA = 2;
    public static final int MX = 3;
    public static final int PTR = 4;
    public static final int TXT = 5;
    public static final int SPF = 6;

    /**
     * The hostname to be resolved
     */
    private final String hostname;
    
    /**
     * The record type to look for
     */
    private final int recordType;

    public DNSRequest(String hostname, int recordType) throws NoneException {
        if (recordType == MX || recordType == A || recordType == AAAA) {
            try {
                Name.fromString(hostname);
            } catch (TextParseException e) {
                throw new NoneException(e.getMessage());
            }
        }
        this.hostname = hostname;
        this.recordType = recordType;
    }

    /**
     * Return the hostname to process the request for
     * 
     * @return the hostname
     */
    public final String getHostname() {
        return hostname;
    }

    /**
     * Return the RecordType which is use for this request
     * 
     * @return the RecordType
     */
    public final int getRecordType() {
        return recordType;
    }

    /**
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return getHostname()+"#"+getRecordType();
    }
}
