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

/**
 * 
 * Implementations of this interface should handle parsing of SPFRecords
 */
public interface SPFRecordParser {

    /**
     * This Method parse the given spf record and checks for syntax
     * 
     * parse can be called by multiple concurrent threads.
     * 
     * @param spfRecord
     *            The String which represent the spf record in dns
     * @return result The SPF1Record
     * @throws PermErrorException
     *             Get thrown if an syntax error was detected
     * @throws NoneException
     *             Get thrown if no spf record could be found
     * @throws NeutralException Get thrown if an empty spf record was found 
     */
    public SPF1Record parse(String spfRecord) throws PermErrorException,
            NoneException, NeutralException;

}