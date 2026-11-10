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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.apache.james.jspf.impl.DNSServiceAsynchSimulator;
import org.apache.james.jspf.impl.SPF;
import org.junit.Test;

public class StagedMultipleSPFExecutorIntegrationTest {

    private static final Map<String, String> RECORDS = Map.of(
        "example.com", "v=spf1 +all",
        "include.example.com", "v=spf1 include:broken.example.com -all",
        "redirect.example.com", "v=spf1 redirect=broken.example.com");

    // fails the lookups of broken.example.com with an unchecked exception, as dnsjava may do on an answer it
    // cannot handle
    private static final DNSService DNS = new DNSService() {
        public List<String> getRecords(DNSRequest request) {
            if (request.getHostname().equals("broken.example.com")) {
                throw new IllegalStateException("answer dnsjava cannot handle");
            }
            String record = RECORDS.get(request.getHostname());
            return request.getRecordType() == DNSRequest.TXT && record != null ? new ArrayList<>(List.of(record)) : null;
        }

        public CompletionStage<List<String>> getRecordsAsync(DNSRequest request) {
            return CompletableFuture.completedFuture(getRecords(request));
        }

        public List<String> getLocalDomainNames() {
            return List.of("localhost");
        }

        public void setTimeOut(int timeOut) {
        }

        public int getRecordLimit() {
            return 10;
        }

        public void setRecordLimit(int recordLimit) {
        }
    };

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupError() {
        checkUnexpectedLookupError(false, "broken.example.com");
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupErrorWhenMultiThreaded() {
        checkUnexpectedLookupError(true, "broken.example.com");
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupErrorInAnInclude() {
        checkUnexpectedLookupError(false, "include.example.com");
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupErrorInAnIncludeWhenMultiThreaded() {
        checkUnexpectedLookupError(true, "include.example.com");
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupErrorInARedirect() {
        checkUnexpectedLookupError(false, "redirect.example.com");
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorOnAnUnexpectedLookupErrorInARedirectWhenMultiThreaded() {
        checkUnexpectedLookupError(true, "redirect.example.com");
    }

    @Test(timeout = 10000)
    public void shouldReturnTempErrorWhenTheLookupServiceThrows() {
        DNSAsynchLookupService simulator = new DNSServiceAsynchSimulator(DNS, false);
        // fails instead of answering an error
        DNSAsynchLookupService throwing = (request, id, responseQueue) -> {
            if (request.getHostname().equals("broken.example.com")) {
                throw new IllegalStateException("lookup service failure");
            }
            simulator.getRecordsAsynch(request, id, responseQueue);
        };
        SPF spf = new SPF(DNS, new StagedMultipleSPFExecutor(throwing));

        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, spf.checkSPF("1.2.3.4", "foo@broken.example.com", "broken.example.com").getResult());
        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, spf.checkSPF("1.2.3.4", "foo@include.example.com", "include.example.com").getResult());
        assertEquals(SPFErrorConstants.PASS_CONV, spf.checkSPF("1.2.3.4", "foo@example.com", "example.com").getResult());
    }

    @Test(timeout = 10000)
    public void shouldGoOnWhenTheLookupServiceThrowsAfterQueuingTheLookup() {
        DNSAsynchLookupService simulator = new DNSServiceAsynchSimulator(DNS, false);
        // queues the lookup, so that it is answered, then fails
        DNSAsynchLookupService throwing = (request, id, responseQueue) -> {
            simulator.getRecordsAsynch(request, id, responseQueue);
            if (request.getHostname().equals("broken.example.com")) {
                throw new IllegalStateException("lookup service failure");
            }
        };
        SPF spf = new SPF(DNS, new StagedMultipleSPFExecutor(throwing));

        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, spf.checkSPF("1.2.3.4", "foo@broken.example.com", "broken.example.com").getResult());
        // the second answer of the failed lookup does not end the executor
        assertEquals(SPFErrorConstants.PASS_CONV, spf.checkSPF("1.2.3.4", "foo@example.com", "example.com").getResult());
    }

    @Test(timeout = 10000)
    public void anInterruptedWaitForAResponseShouldKeepTheInterrupt() {
        Thread.currentThread().interrupt();

        assertNull(new StagedMultipleSPFExecutor.ResponseQueueImpl().removeResponse());
        assertTrue(Thread.interrupted());
    }

    private void checkUnexpectedLookupError(boolean multiThread, String domain) {
        SPF spf = new SPF(DNS, new StagedMultipleSPFExecutor(new DNSServiceAsynchSimulator(DNS, multiThread)));

        // RFC 7208 4.4: a DNS error ends the check as temperror, as with the two other executors
        assertEquals(SPFErrorConstants.TEMP_ERROR_CONV, spf.checkSPF("1.2.3.4", "foo@" + domain, domain).getResult());
        // the executor still checks
        assertEquals(SPFErrorConstants.PASS_CONV, spf.checkSPF("1.2.3.4", "foo@example.com", "example.com").getResult());
    }
}
