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

package org.apache.james.jspf.policies.local;

import static org.junit.Assert.assertEquals;

import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.impl.DefaultTermsFactory;
import org.apache.james.jspf.parser.RFC4408SPF1Parser;
import org.apache.james.jspf.policies.NeutralIfNotMatchPolicy;
import org.junit.Test;

public class FallbackPolicyTest {
    private static final SPFRecordParser PARSER = new RFC4408SPF1Parser(new DefaultTermsFactory());

    @Test
    public void aFallbackRecordShouldNotKeepTheModifiersAddedToItInACheck() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("example.com.", "v=spf1 -all");

        // as the policies after the fallback do in a check
        new NeutralIfNotMatchPolicy().getSPFRecord("example.com.", policy.getSPFRecord("example.com.", null));

        assertEquals(0, policy.getSPFRecord("example.com.", null).getModifiers().size());
    }

    @Test
    public void anOverrideRecordShouldNotKeepTheModifiersAddedToItInACheck() throws Exception {
        OverridePolicy policy = new OverridePolicy(PARSER);
        policy.addEntry("example.com.", "v=spf1 -all");

        new NeutralIfNotMatchPolicy().getSPFRecord("example.com.", policy.getSPFRecord("example.com."));

        assertEquals(0, policy.getSPFRecord("example.com.").getModifiers().size());
    }
}
