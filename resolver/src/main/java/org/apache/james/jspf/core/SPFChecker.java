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

import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.TempErrorException;

/**
 * Interface for the SPFChecker service.
 */
public interface SPFChecker {

    /**
     * Run check for SPF with the given values.
     * 
     * @param spfData
     *            The SPF1Data which should be used to run the check
     * @throws PermErrorException
     *             Get thrown if an error was detected
     * @throws NoneException
     *             Get thrown if no Record was found
     * @throws TempErrorException
     *             Get thrown if a DNS problem was detected
     * @throws NeutralException
     *             Get thrown if the result should be neutral
     * @throws NoneException 
     */
    public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
            TempErrorException, NeutralException, NoneException;
}