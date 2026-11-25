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

package org.apache.james.jspf.terms;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.MacroExpand;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.impl.SPF;
import org.junit.Test;

public class ExpModifierTest {

    private static final String HELO = ("a".repeat(62) + ".").repeat(3) + "a".repeat(60) + ".com";

    private static DNSService dns(Map<String, String> txtRecords) {
        return new DNSService() {
            public List<String> getRecords(DNSRequest request) {
                String record = txtRecords.get(request.getHostname());
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
    }

    @Test
    public void anExplanationShouldBeExpanded() {
        SPF spf = new SPF(dns(Map.of(
            "example.com", "v=spf1 -all exp=exp.example.com",
            "exp.example.com", "%{h} is not allowed")));

        SPFResult result = spf.checkSPF("1.2.3.4", "foo@example.com", HELO);

        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
        assertEquals(HELO + " is not allowed", result.getExplanation());
    }

    @Test
    public void anExplanationExpandedPastTheLimitShouldBeIgnored() {
        // about 64 KB of macros, each growing into the whole HELO name
        SPF spf = new SPF(dns(Map.of(
            "example.com", "v=spf1 -all exp=exp.example.com",
            "exp.example.com", "%{h}".repeat(16000))));

        SPFResult result = spf.checkSPF("1.2.3.4", "foo@example.com", HELO);

        // RFC 7208 6.2: as if no exp= was given, so the default explanation
        assertEquals(SPFErrorConstants.FAIL_CONV, result.getResult());
        assertTrue(result.getExplanation(), result.getExplanation().length() <= MacroExpand.MAX_EXPLANATION_LENGTH);
        assertTrue(result.getExplanation(), result.getExplanation().startsWith("http://www.openspf.org/why.html?sender="));
    }
}
