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


package org.apache.james.jspf.executor;

import static org.junit.Assert.assertEquals;

import java.util.concurrent.TimeUnit;

import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.junit.Test;

public class FutureSPFResultTest {

    @Test(timeout = 10000)
    public void getResultShouldGiveTempErrorWhenTheResultIsNotSetInTime() {
        FutureSPFResult result = new FutureSPFResult();

        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, result.getResult(50, TimeUnit.MILLISECONDS));
    }

    @Test(timeout = 10000)
    public void getResultShouldGiveTheResultOnceSet() {
        FutureSPFResult result = new FutureSPFResult();
        SPFSession session = new SPFSession("a_user@example.com", "example.com", "1.2.3.4");
        session.setCurrentResultExpanded(SPFErrorConstants.PASS_CONV);
        result.setSPFResult(session);

        assertEquals(SPFErrorConstants.PASS_CONV, result.getResult(50, TimeUnit.MILLISECONDS));
    }
}
