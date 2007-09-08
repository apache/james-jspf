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

import org.apache.james.jspf.dns.DNSResponse;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

/**
 * 
 * Listeners which should get called for a SPFCheck when the DNSResponse is aviable should implement 
 * this interface.
 */
public interface SPFCheckerDNSResponseListener {
    
    /**
     * Continue the check for SPF with the given values and the given DNSResponse
     * 
     * @param response
     *             The DNSResponse which should be used to run the check
     * @param session
     *             The SPFSession which should be used to run the check
     * @throws PermErrorException
     *             Get thrown if an error was detected
     * @throws NoneException
     *             Get thrown if no Record was found
     * @throws TempErrorException
     *             Get thrown if a DNS problem was detected
     * @throws NeutralException  
     *             Get thrown if the result should be neutral
     */
    public DNSLookupContinuation onDNSResponse(DNSResponse response, SPFSession session) throws PermErrorException, NoneException, TempErrorException, NeutralException;

}
