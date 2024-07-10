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

package org.apache.james.jspf;

import org.junit.Test;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.impl.DefaultSPF;
import org.apache.james.jspf.impl.SPF;

public class SpfVerifierTest {
    @Test
    public void shouldHandleRecordNotFound() {
        String ipAddress = "103.52.180.162";
        String hostName = "FMTA1-162.ncdelivery04.com";
        String from = "17191683732756478-181603-1-mxscout.com@delivery.forumofsecrets.com";

        final SPF spfChecker = new DefaultSPF();
        spfChecker.setUseBestGuess(true);

        SPFResult spfResult = spfChecker.checkSPF(ipAddress, from, hostName);
        spfResult.getResult();
    }
}
