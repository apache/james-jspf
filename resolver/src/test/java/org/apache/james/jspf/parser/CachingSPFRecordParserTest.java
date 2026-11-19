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

package org.apache.james.jspf.parser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.executor.AsynchronousSPFExecutor;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.executor.SynchronousSPFExecutor;
import org.apache.james.jspf.helpers.FakeResolver;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.apache.james.jspf.impl.DefaultTermsFactory;
import org.apache.james.jspf.impl.SPF;
import org.apache.james.jspf.wiring.WiringServiceTable;
import org.junit.Before;
import org.junit.Test;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.TXTRecord;

public class CachingSPFRecordParserTest {

    private static final class CountingParser implements SPFRecordParser {
        private final SPFRecordParser parser = new RFC4408SPF1Parser(new DefaultTermsFactory(new WiringServiceTable()));
        private final AtomicInteger parsed = new AtomicInteger();

        public SPF1Record parse(String spfRecord) throws PermErrorException, NoneException, NeutralException {
            parsed.incrementAndGet();
            return parser.parse(spfRecord);
        }
    }

    private CountingParser counting;

    @Before
    public void setUp() {
        counting = new CountingParser();
        Lookup.getDefaultCache(DClass.IN).clearCache();
    }

    @Test
    public void shouldParseARecordOnce() throws Exception {
        CachingSPFRecordParser parser = new CachingSPFRecordParser(counting);

        parser.parse("v=spf1 ip4:192.0.2.0/24 -all");
        parser.parse("v=spf1 ip4:192.0.2.0/24 -all");

        assertEquals(1, counting.parsed.get());
    }

    @Test
    public void shouldGiveANewRecordSharingTheTerms() throws Exception {
        CachingSPFRecordParser parser = new CachingSPFRecordParser(counting);

        SPF1Record first = parser.parse("v=spf1 ip4:192.0.2.0/24 -all");
        first.getModifiers().add(null);
        SPF1Record second = parser.parse("v=spf1 ip4:192.0.2.0/24 -all");

        assertNotSame(first, second);
        assertEquals(0, second.getModifiers().size());
        assertEquals(2, second.getDirectives().size());
        assertSame(first.getDirectives().get(0), second.getDirectives().get(0));
    }

    @Test
    public void shouldNotKeepAnInvalidRecord() throws Exception {
        CachingSPFRecordParser parser = new CachingSPFRecordParser(counting);

        for (int i = 0; i < 2; i++) {
            try {
                parser.parse("v=spf1 xip4:192.0.2.1");
                fail("expected a permerror");
            } catch (PermErrorException e) {
                // expected
            }
        }

        assertEquals(2, counting.parsed.get());
        assertEquals(0, parser.size());
    }

    @Test
    public void shouldNotKeepALongRecord() throws Exception {
        CachingSPFRecordParser parser = new CachingSPFRecordParser(counting, 10, 30);

        parser.parse("v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all");
        parser.parse("v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all");

        assertEquals(2, counting.parsed.get());
        assertEquals(0, parser.size());
    }

    @Test
    public void shouldKeepAtMostTheGivenNumberOfRecords() throws Exception {
        CachingSPFRecordParser parser = new CachingSPFRecordParser(counting, 2, 2048);

        parser.parse("v=spf1 ip4:192.0.2.1 -all");
        parser.parse("v=spf1 ip4:192.0.2.2 -all");
        parser.parse("v=spf1 ip4:192.0.2.1 -all");
        parser.parse("v=spf1 ip4:192.0.2.3 -all");
        // the least recently used one was dropped
        parser.parse("v=spf1 ip4:192.0.2.1 -all");
        parser.parse("v=spf1 ip4:192.0.2.2 -all");

        assertEquals(2, parser.size());
        assertEquals(4, counting.parsed.get());
    }

    private static FakeResolver includeTree() throws Exception {
        FakeResolver resolver = new FakeResolver();
        resolver.addRecord(new TXTRecord(Name.fromString("example.com."), DClass.IN, 30L,
            "v=spf1 ip4:192.0.2.0/24 include:inc.example.com a:a.example.com mx exists:%{i}.ex.example.com -all exp=explain.example.com"));
        resolver.addRecord(new TXTRecord(Name.fromString("inc.example.com."), DClass.IN, 30L, "v=spf1 ip6:2001:db8::/32 ~all"));
        resolver.addRecord(new TXTRecord(Name.fromString("explain.example.com."), DClass.IN, 30L, "%{i} is not allowed for %{d}"));
        resolver.addRecord(new ARecord(Name.fromString("a.example.com."), DClass.IN, 30L, InetAddress.getByName("198.51.100.1")));
        resolver.addRecord(new MXRecord(Name.fromString("example.com."), DClass.IN, 30L, 10, Name.fromString("mx.example.com.")));
        resolver.addRecord(new ARecord(Name.fromString("mx.example.com."), DClass.IN, 30L, InetAddress.getByName("198.51.100.2")));
        resolver.addRecord(new AAAARecord(Name.fromString("mx.example.com."), DClass.IN, 30L, InetAddress.getByName("2001:db9::2")));
        resolver.addRecord(new ARecord(Name.fromString("203.0.113.7.ex.example.com."), DClass.IN, 30L, InetAddress.getByName("127.0.0.2")));
        return resolver;
    }

    private static final String[] CLIENTS = {"192.0.2.5", "2001:db8::1", "198.51.100.1", "198.51.100.2", "203.0.113.7",
        "203.0.113.8", "10.0.0.1", "2001:db9::2", "2001:db9::3"};

    private static String check(SPF spf, String client) {
        SPFResult result = spf.checkSPF(client, "user@example.com", "example.com");
        return result.getResult() + " " + result.getExplanation();
    }

    private void checkConcurrently(SPF spf) throws Exception {
        Map<String, String> expected = new LinkedHashMap<>();
        for (String client : CLIENTS) {
            expected.put(client, check(spf, client));
        }
        assertEquals("pass ", expected.get("192.0.2.5"));
        assertEquals("pass ", expected.get("2001:db8::1"));
        assertEquals("pass ", expected.get("203.0.113.7"));
        assertEquals("fail 203.0.113.8 is not allowed for example.com", expected.get("203.0.113.8"));
        assertEquals("pass ", expected.get("2001:db9::2"));

        ExecutorService threads = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> checks = new ArrayList<>();
            for (int n = 0; n < 400; n++) {
                String client = CLIENTS[n % CLIENTS.length];
                checks.add(threads.submit(() -> assertEquals(client, expected.get(client), check(spf, client))));
            }
            for (Future<?> check : checks) {
                check.get(60, TimeUnit.SECONDS);
            }
        } finally {
            threads.shutdownNow();
        }
    }

    @Test
    public void concurrentSynchronousChecksShouldShareTheParsedRecords() throws Exception {
        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(includeTree());
        checkConcurrently(new SPF(dns, new SynchronousSPFExecutor(dns)));
    }

    @Test
    public void concurrentAsynchronousChecksShouldShareTheParsedRecords() throws Exception {
        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(includeTree());
        checkConcurrently(new SPF(dns, new AsynchronousSPFExecutor(dns)));
    }
}
