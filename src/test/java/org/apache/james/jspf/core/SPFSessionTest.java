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
import org.apache.james.jspf.exceptions.PermErrorException;

import junit.framework.TestCase;

public class SPFSessionTest extends TestCase {

    /*
     * Test method for 'org.apache.james.jspf.core.SPF1Data.getMacroIpAddress()'
     */
    public void testGetMacroIpAddress() throws PermErrorException, NoneException {
        SPFSession d = new SPFSession("mailfrom@fromdomain.com","helodomain.com","2001:DB8::CB01");
        assertEquals("2.0.0.1.0.D.B.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.C.B.0.1",d.getMacroIpAddress());
    }

}
