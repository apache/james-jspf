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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

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

    @Test
    public void anEntryShouldBeForTheDomainItNames() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("example.com", "v=spf1 +all");

        assertNotNull(policy.getSPFRecord("example.com", null));
    }

    @Test
    public void anEntryShouldBeForItsDomainWhateverTheCaseAndTrailingDot() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("Example.COM.", "v=spf1 +all");

        assertNotNull(policy.getSPFRecord("example.com", null));
        assertNotNull(policy.getSPFRecord("EXAMPLE.com.", null));
    }

    @Test
    public void anEntryShouldNotBeForAnotherDomainEndingWithItsName() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("example.com.", "v=spf1 +all");

        assertNull(policy.getSPFRecord("badexample.com.", null));
        assertNull(policy.getSPFRecord("foo.example.com.", null));
    }

    @Test
    public void aWildcardEntryShouldBeForTheDomainsUnderItsDomain() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("*.example.com", "v=spf1 +all");

        assertNotNull(policy.getSPFRecord("foo.example.com", null));
        assertNotNull(policy.getSPFRecord("a.b.example.com.", null));
        assertNull(policy.getSPFRecord("example.com", null));
        assertNull(policy.getSPFRecord("badexample.com", null));
        assertNull(policy.getSPFRecord(".example.comcom.", null));
    }

    @Test
    public void aWildcardEntryShouldNotBeForALabelHoldingADot() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("*.example.com", "v=spf1 +all");

        // the labels "mail.example" and "com": a domain under com, not under example.com
        assertNull(policy.getSPFRecord("mail\\.example.com", null));
    }

    @Test
    public void aWildcardEntryShouldBeForALabelEndingWithABackslash() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("*.example.com", "v=spf1 +all");

        // the labels "a\\", "example" and "com": the dot after the escaped backslash separates labels
        assertNotNull(policy.getSPFRecord("a\\\\.example.com", null));
    }

    @Test
    public void aWildcardEntryShouldBeForADomainDnsjavaCannotParse() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("*.example.com", "v=spf1 +all");
        policy.addEntry("*.\u043f\u0440\u0438\u043c\u0435\u0440.com", "v=spf1 +all");

        // not ISO-8859-1: compared as text, label by label all the same
        assertNotNull(policy.getSPFRecord("\u043f\u0440\u0438\u043c\u0435\u0440.example.com", null));
        assertNotNull(policy.getSPFRecord("foo.\u043f\u0440\u0438\u043c\u0435\u0440.com", null));
    }

    @Test
    public void anEntryShouldBeForItsDomainWrittenWithEscapes() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("example.com", "v=spf1 +all");
        policy.addEntry("*.example.org", "v=spf1 +all");

        // \097 is "a"
        assertNotNull(policy.getSPFRecord("ex\\097mple.com", null));
        assertNotNull(policy.getSPFRecord("foo.ex\\097mple.org", null));
    }

    @Test
    public void aPrefixEntryShouldBeForTheDomainsStartingWithItsLabel() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("mail.*", "v=spf1 +all");

        assertNotNull(policy.getSPFRecord("mail.example.org", null));
        assertNull(policy.getSPFRecord("mailer.example.org", null));
    }

    @Test
    public void theEntryOfTheDomainShouldComeBeforeAWildcardEntry() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("*.example.com", "v=spf1 -all");
        policy.addEntry("foo.example.com", "v=spf1 +all");

        assertEquals("[+all]", policy.getSPFRecord("foo.example.com", null).getDirectives().toString());
    }

    @Test
    public void theLongestWildcardEntryShouldComeFirst() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("*.com", "v=spf1 -all");
        policy.addEntry("*.example.com", "v=spf1 +all");

        assertEquals("[+all]", policy.getSPFRecord("foo.example.com", null).getDirectives().toString());
    }

    @Test
    public void theEntryOfPatternsOfTheSameLengthShouldNotDependOnTheirOrder() throws Exception {
        // two patterns of 13 characters with the same hash bucket, so iterated in the order they were added
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("*.example.com", "v=spf1 -all");
        policy.addEntry("aat.example.*", "v=spf1 +all");
        FallbackPolicy reversed = new FallbackPolicy(PARSER);
        reversed.addEntry("aat.example.*", "v=spf1 +all");
        reversed.addEntry("*.example.com", "v=spf1 -all");

        assertEquals(policy.getSPFRecord("aat.example.com", null).getDirectives().toString(),
            reversed.getSPFRecord("aat.example.com", null).getDirectives().toString());
    }

    @Test
    public void anOverrideEntryShouldBeForTheDomainsUnderItsDomain() throws Exception {
        OverridePolicy policy = new OverridePolicy(PARSER);
        policy.addEntry("*.example.com", "v=spf1 -all");

        assertNotNull(policy.getSPFRecord("foo.example.com"));
    }

    @Test
    public void removeEntryShouldRemoveTheEntry() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("example.com.", "v=spf1 +all");

        policy.removeEntry("example.com.");

        assertNull(policy.getSPFRecord("example.com.", null));
    }

    @Test
    public void removeEntryShouldRemoveAWildcardEntry() throws Exception {
        FallbackPolicy policy = new FallbackPolicy(PARSER);
        policy.addEntry("*.example.com", "v=spf1 +all");
        policy.addEntry("foo.example.com", "v=spf1 -all");

        policy.removeEntry("*.example.com");

        assertNull(policy.getSPFRecord("bar.example.com", null));
        assertNotNull(policy.getSPFRecord("foo.example.com", null));
    }
}
