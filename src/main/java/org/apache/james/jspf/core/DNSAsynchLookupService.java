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


/**
 * Interface which should be used to access all necassary DNS-Records
 *  
 */
public interface DNSAsynchLookupService {

    /**
     * Retrieve dns records for the given host asynchronously
     * 
     * @param request the dns request
     * @param id the identification key for the response.
     * @param responsePool the queue where the response will be appended.
     */
    public void getRecordsAsynch(DNSRequest request, Object id,
            final IResponseQueue responsePool);

}