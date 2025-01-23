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
package org.apache.james.jspf.helpers;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.lookup.LookupSession;

import java.io.IOException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class FakeResolverTest {
    private static final Logger logger = LoggerFactory.getLogger(FakeResolverTest.class);
    private static final String DNSZONEFILE = "src/test/resources/dnszones/FakeResolverTest.zone";
    private static String externalNameA = "example.com";
    private static String externalNameAAAA = "example.com";
    private static String externalNameTXT = "example.com";
    private static String externalNameMX = "example.com";
    private static String externalNameCNAME = "www.example.com";
    private static String externalNameNS = "example.com";

    @BeforeClass
    public static void setupAll() throws TextParseException {
        externalNameA = validateName(externalNameA, Type.A, "apache.org", "iana.org");
        externalNameAAAA = validateName(externalNameAAAA, Type.AAAA, "apache.org", "iana.org.");
        externalNameTXT = validateName(externalNameTXT, Type.TXT, "apache.org", "iana.org");
        externalNameMX = validateName(externalNameMX, Type.MX, "apache.org", "iana.org");
        externalNameCNAME = validateName(externalNameCNAME, Type.CNAME, "www.iana.org", "www.github.com");
        externalNameNS = validateName(externalNameNS, Type.NS, "apache.org", "iana.org");
    }

    @Before
    public void setup() {
        Lookup.getDefaultCache(DClass.IN).clearCache();
    }

    @Test
    public void shouldResolveA() throws IOException {
        String domain = "fakeresolver.zone";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(domain, DNSZONEFILE);

        Lookup.setDefaultResolver(fakeResolver);
        Record[] found = new Lookup(Name.fromString("shouldResolveA", Name.fromString(domain)), Type.A).run();
        assertNotNull(found);
        assertEquals(1, found.length);
    }

    @Test
    public void shouldRejectInvalidDomain() throws IOException {
        FakeResolver fakeResolver = new FakeResolver();
        assertThrows(IllegalArgumentException.class, () -> fakeResolver.fromZoneFile(null, ""));
    }

    @Test
    public void shouldReturnList() throws IOException {
        String domain = "fakeresolver.zone";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(domain, DNSZONEFILE);
        logger.info("Size: {}", fakeResolver.getRecords().size());
        assertFalse(fakeResolver.getRecords().isEmpty());
    }

    @Test
    public void shouldResolveTXT() throws IOException {
        String domain = "fakeresolver.zone";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(domain, DNSZONEFILE);

        List<Record> found = lookup(Name.fromString("shouldResolveTXT", Name.fromString(domain)), Type.TXT, fakeResolver);
        assertNotNull(found);
        assertEquals(2, found.size());
        found.forEach(r -> assertEquals(Type.TXT, r.getType()));
    }

    @Test
    public void shouldMatchResolvedTXT() throws IOException {
        recordsMatch(Name.fromString(externalNameTXT), Type.TXT);
    }

    @Test
    public void shouldResolveMX() throws IOException {
        String domain = "fakeresolver.zone";
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(domain, DNSZONEFILE);

        List<Record> found = lookup(Name.fromString("shouldResolveMX", Name.fromString(domain)), Type.MX, fakeResolver);
        assertNotNull(found);
        assertEquals(1, found.size());
        assertEquals(10, ((MXRecord) found.get(0)).getPriority());
        found.forEach(r -> assertEquals(Type.MX, r.getType()));
    }

    @Test
    public void shouldMatchResolvedMX() throws IOException {
        recordsMatch(Name.fromString(externalNameMX), Type.MX);
    }

    @Test
    public void shouldResolveNS() throws IOException {
        String domain = "fakeresolver.zone";
        List<String> nsIp = Arrays.asList("192.0.2.11", "192.0.2.12", "192.0.2.13");
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.fromZoneFile(domain, DNSZONEFILE);

        List<Record> found = lookup(Name.fromString("shouldResolveNS", Name.fromString(domain)), Type.NS, fakeResolver);
        assertNotNull(found);
        assertEquals(3, found.size());
        found.forEach(r -> {
            assertEquals(Type.NS, r.getType());
            List<Record> nsA = lookup(((NSRecord) r).getTarget(), Type.A, fakeResolver);
            assertEquals(1, nsA.size());
            assertTrue(nsIp.contains(((ARecord) nsA.get(0)).getAddress().getHostAddress()));
        });
    }

    @Test
    public void shouldMatchResolvedNS() throws IOException {
        recordsMatch(Name.fromString(externalNameNS), Type.NS);
    }

    @Test
    public void shouldResolveExternallyCNAME() throws IOException {
        String domain = "fakeresolver.zone";
        FakeResolver fakeResolver = new FakeResolver(new SimpleResolver());
        fakeResolver.fromZoneFile(domain, DNSZONEFILE);

        List<Record> found = lookup(Name.fromString("shouldResolveExternallyCNAME", Name.fromString(domain)), Type.A, fakeResolver);
        assertNotNull(found);
        assertFalse(found.isEmpty());
        found.forEach(r -> assertEquals(Type.A, r.getType()));
    }

    @Test
    public void shouldMatchResolvedCNAME() throws IOException {
        recordsMatch(Name.fromString(externalNameCNAME), Type.CNAME);
    }

    @Test
    public void shouldMatchResolvedA() throws IOException {
        recordsMatch(Name.fromString(externalNameA), Type.A);
    }

    @Test
    public void shouldMatchResolvedAAAA() throws IOException {
        recordsMatch(Name.fromString(externalNameAAAA), Type.AAAA);
    }

    @Test
    public void shouldResolveExternallyLegacy() throws IOException {
        String domain = "fakeresolver.zone";
        FakeResolver fakeResolver = new FakeResolver(new SimpleResolver());
        fakeResolver.fromZoneFile(domain, DNSZONEFILE);

        Record[] found = new Lookup(Name.fromString(externalNameCNAME), Type.A).run();
        assertNotNull(found);
        assertTrue(found.length > 0);
        Arrays.asList(found).forEach(r -> assertEquals(Type.A, r.getType()));
    }

    @Test
    public void shouldReturnNotImplementedSetPort() {
        assertThrows(UnsupportedOperationException.class, () -> new FakeResolver().setPort(0));
    }

    @Test
    public void shouldReturnNotImplementedSetTCP() {
        assertThrows(UnsupportedOperationException.class, () -> new FakeResolver().setTCP(false));
    }

    @Test
    public void shouldReturnNotImplementedSetIgnoreTruncation() {
        assertThrows(UnsupportedOperationException.class, () -> new FakeResolver().setIgnoreTruncation(false));
    }

    @Test
    public void shouldReturnNotImplementedSetEDNS() {
        assertThrows(UnsupportedOperationException.class, () -> new FakeResolver().setEDNS(0));
    }

    @Test
    public void shouldReturnNotImplementedSetTSIGKey() {
        assertThrows(UnsupportedOperationException.class, () -> new FakeResolver().setTSIGKey(null));
    }

    @Test
    public void shouldReturnNotImplementedSetTimeout() {
        assertThrows(UnsupportedOperationException.class, () -> new FakeResolver().setTimeout(Duration.ZERO));
    }

    @Test
    public void shouldGenerateNStrings() {
        assertEquals(11, FakeResolver.genNRandomTXTRecords("test.", 11).size());
    }

    @Test
    public void shouldNotGenerateNStrings() {
        assertThrows(IllegalArgumentException.class, () -> FakeResolver.genNRandomTXTRecords("", 11).size());
    }

    @Test
    public void shouldReturnOneRecord() throws UnknownHostException, TextParseException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.setRecord(new TXTRecord(Name.fromString("a."), DClass.IN, 60L, "a"));
        assertEquals(1, fakeResolver.getRecords().size());
    }

    @Test
    public void shouldReturnTwoRecords() throws UnknownHostException, TextParseException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.setRecords(Arrays.asList(new Record[]{
                        new TXTRecord(Name.fromString("a."), DClass.IN, 60L, "a"),
                        new TXTRecord(Name.fromString("b."), DClass.IN, 30L, "b")
                })
        );
        assertEquals(2, fakeResolver.getRecords().size());
    }

    @Test
    public void shouldReturnThreeRecords() throws UnknownHostException, TextParseException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.setRecords(Arrays.asList(new Record[]{
                        new TXTRecord(Name.fromString("a."), DClass.IN, 60L, "a"),
                        new TXTRecord(Name.fromString("b."), DClass.IN, 30L, "b")
                })
        );
        fakeResolver.addRecord(new TXTRecord(Name.fromString("c."), DClass.IN, 30L, "c"));
        assertEquals(3, fakeResolver.getRecords().size());
    }

    @Test
    public void shouldReturnFourRecords() throws UnknownHostException, TextParseException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.setRecords(Arrays.asList(new Record[]{
                        new TXTRecord(Name.fromString("a."), DClass.IN, 60L, "a"),
                        new TXTRecord(Name.fromString("b."), DClass.IN, 30L, "b")
                })
        );
        fakeResolver.addRecords(Arrays.asList(new Record[]{
                        new TXTRecord(Name.fromString("c."), DClass.IN, 60L, "c"),
                        new TXTRecord(Name.fromString("d."), DClass.IN, 30L, "d")
                })
        );
        assertEquals(4, fakeResolver.getRecords().size());
    }

    @Test
    public void shouldReturnEmpty() throws UnknownHostException, TextParseException {
        FakeResolver fakeResolver = new FakeResolver();
        fakeResolver.setRecord(new TXTRecord(Name.fromString("a."), DClass.IN, 60L, "a"));
        fakeResolver.clearRecords();
        assertEquals(0, fakeResolver.getRecords().size());
    }

    private void recordsMatch(Name name, int type) throws UnknownHostException {
        FakeResolver fakeResolver = new FakeResolver();
        SimpleResolver simpleResolver = new SimpleResolver();

        RRset resultFakeResolver = lookupRRset(name, type, fakeResolver);
        RRset resultSimpleResolver = lookupRRset(name, type, simpleResolver);

        assertTrue(String.format("Records for name '%s' type '%s' are different.\n\tResolvers: [%s, %s],\n\tRecords:\n\t\t[%s,\n\t\t%s]",
                name, Type.string(type),
                simpleResolver, fakeResolver,
                resultSimpleResolver, resultFakeResolver), rrMatch(resultSimpleResolver, resultFakeResolver)
        );
    }

    private boolean rrMatch(RRset rr1, RRset rr2) {
        int count = 0;
        for (Record r1 : rr1.rrs()) {
            for (Record r2 : rr2.rrs()) {
                if (r1.equals(r2)) {
                    count++;
                }
            }
        }
        return count == rr1.size() && count == rr2.size();
    }

    private RRset lookupRRset(Name name, int type, Resolver resolver) {
        RRset rr = new RRset();
        try {
            LookupSession lookup = LookupSession.defaultBuilder().resolver(resolver).build();
            lookup.lookupAsync(name, type)
                    .whenComplete((a, ex) -> {
                        a.getRecords().forEach(rr::addRR);
                        if (ex != null) {
                            throw new RuntimeException(ex);
                        }
                    })
                    .toCompletableFuture().get();
        } catch (ExecutionException | InterruptedException e) {
            logger.error("Error during dns lookup: ", e);
            return new RRset();
        }
        return rr;
    }

    private List<Record> lookup(Name name, int type, Resolver resolver) {
        return lookupRRset(name, type, resolver).rrs();
    }

    private static boolean isValidRecord(String name, int type) throws TextParseException {
        return new Lookup(name, type).run() != null;
    }

    private static String validateName(String name, int type, String... fallbacks) throws TextParseException {
        if (!isValidRecord(name, type)) {
            for (String f : fallbacks) {
                if (isValidRecord(f, type)) {
                    return f;
                }
            }
            logger.error("Name '{}' of type '{}' is invalid.", name, Type.string(type));
            return "";
        }
        return name;
    }
}
