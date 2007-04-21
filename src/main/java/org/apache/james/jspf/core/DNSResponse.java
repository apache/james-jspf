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

import org.apache.james.jspf.core.DNSService.TimeoutException;

import java.util.List;

/**
 * Represent a DNSResponse
 *
 */
public class DNSResponse {
    
    private List response;
    
    private TimeoutException exception;
    
    public DNSResponse(TimeoutException exception) {
        this.exception = exception;
        this.response = null;
    }
    
    public DNSResponse(List response) {
        this.exception = null;
        this.response = response;
    }
    
    /**
     * Returns the DNS response
     * 
     * @return the dns repsonse
     * @throws TimeoutException get thrown if an timeout was returned while tried to 
     *         process a dns request
     */
    public List getResponse() throws TimeoutException {
        if (exception != null) {
            throw exception;
        } else {
            return response;
        }
    }

}
