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

import org.apache.james.jspf.core.exceptions.TimeoutException;

import java.util.List;

/**
 * Interface which should be used to access all necassary DNS-Records
 *  
 */
public interface DNSService {
    
    /**
     * Retrieve dns records for the given host
     * 
     * @param request the dns request
     * @return an array of Strings representing the records
     * @throws TimeoutException
     */
    public List getRecords(DNSRequest request) throws TimeoutException;

    /**
     * Try to get all domain names for the running host
     * 
     * @return names A List contains all domain names which could resolved
     */
    public List getLocalDomainNames();

    /**
     * Set the timeout for DNS-Requests
     * 
     * @param timeOut The timeout in seconds
     */
    public void setTimeOut(int timeOut);
    
    /**
     * @return the current record limit
     */
    public int getRecordLimit();

    /**
     * Sets a new limit for the number of records for MX and PTR lookups.
     * 
     * @param recordLimit the new limit (0 => unlimited)
     */
    public void setRecordLimit(int recordLimit);

}