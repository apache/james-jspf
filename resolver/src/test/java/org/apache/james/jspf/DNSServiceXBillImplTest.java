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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.apache.james.jspf.helpers.AnsweringResolver;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.junit.Test;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.lookup.LookupFailedException;
import org.xbill.DNS.lookup.LookupSession;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DNSServiceXBillImplTest {
    // rcode YXRRSET, and the answer ". CNAME .": a CNAME of the root, not of the name queried
    private static final String CNAME_OF_THE_ROOT = "AAGBJwABAAEAAAAAAAABAAHADAAFAAEAAA4QAAEA";

    @Test
    public void testGetLocalDomainNames() throws UnknownHostException {
        assertFalse(new DNSServiceXBillImpl().getLocalDomainNames().isEmpty());
    }

    @Test
    public void testMultipleStrings() throws Exception {
        Record[] rr = new Record[]{
                TXTRecord.fromString(Name.fromString("test.local."),
                        Type.TXT, DClass.IN, 0, "\"string \" \"concatenated\"", Name.fromString("local."))};
        List<String> records = DNSServiceXBillImpl.convertRecordsToList(rr);
        assertNotNull(records);
        assertEquals("string concatenated", records.get(0));

        rr = new Record[]{
                TXTRecord.fromString(Name.fromString("test.local."),
                        Type.TXT, DClass.IN, 0, "string", Name.fromString("local."))};
        records = DNSServiceXBillImpl.convertRecordsToList(rr);
        assertNotNull(records);
        assertEquals("string", records.get(0));

        rr = new Record[]{
                TXTRecord.fromString(Name.fromString("test.local."),
                        Type.TXT, DClass.IN, 0, "\"quoted string\"", Name.fromString("local."))};
        records = DNSServiceXBillImpl.convertRecordsToList(rr);
        assertNotNull(records);
        assertEquals("quoted string", records.get(0));

        rr = new Record[]{
                SPFRecord.fromString(Name.fromString("test.local."),
                        Type.SPF, DClass.IN, 0, "\"quot\" \"ed st\" \"ring\"", Name.fromString("local."))};
        records = DNSServiceXBillImpl.convertRecordsToList(rr);
        assertNotNull(records);
        assertEquals("quoted string", records.get(0));
    }

    @Test
    public void convertRecordsToListShouldIgnoreAnswersWithoutData() throws Exception {
        // an UPDATE message holding a TXT answer of RDLENGTH 0: dnsjava parses it as an EmptyRecord of type TXT
        byte[] message = Base64.getDecoder().decode("AAEpgAABAAEAAAAAB2V4YW1wbGUDY29tAIGDAAHADAAQAAEAAA4QAABs");
        Record[] answer = new Message(message).getSection(Section.ANSWER).toArray(new Record[0]);

        assertEquals(Type.TXT, answer[0].getType());
        assertNull(DNSServiceXBillImpl.convertRecordsToList(answer));
    }

    @Test(timeout = 10000)
    public void getRecordsShouldReportADnsErrorForAnAnswerDnsjavaCannotProcess() throws Exception {
        // opcode UPDATE, and the answer "example.com CNAME" of RDLENGTH 0: dnsjava's Lookup throws ClassCastException
        byte[] message = Base64.getDecoder().decode("AAErAAABAAEAAAAAB2V4YW1wbGUDY29tAAAQAAHADAAFAAAAAA5RAABj");
        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(new AnsweringResolver(message));
        Lookup.getDefaultCache(DClass.IN).clearCache();

        try {
            dns.getRecords(new DNSRequest("example.com", DNSRequest.TXT));
            fail("the lookup should fail");
        } catch (TimeoutException e) {
            // DNSService declares only TimeoutException: a DNS error (RFC 7208 4.4)
        }
    }

    @Test(timeout = 10000)
    public void getRecordsShouldReportADnsErrorForAnExtendedErrorRcode() throws Exception {
        // BADVERS, of which dnsjava's Lookup reads only the header bits: NOERROR
        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(AnsweringResolver.withRcode(Rcode.BADVERS));

        try {
            dns.getRecords(new DNSRequest("badvers.example.com", DNSRequest.TXT));
            fail("the lookup should fail");
        } catch (TimeoutException e) {
            // an error rcode: a DNS error (RFC 7208 4.4)
        }
    }

    @Test(timeout = 10000)
    public void getRecordsAsyncShouldReportADnsErrorForAnAnswerDnsjavaCannotProcess() throws Exception {
        // opcode UPDATE, and the answer "example.com CNAME" of RDLENGTH 0: dnsjava's LookupSession fails with
        // ClassCastException
        byte[] message = Base64.getDecoder().decode("AAErAAABAAEAAAAAB2V4YW1wbGUDY29tAAAQAAHADAAFAAAAAA5RAABj");
        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(new AnsweringResolver(message));

        CompletableFuture<List<String>> records = dns.getRecordsAsync(new DNSRequest("example.com", DNSRequest.TXT))
            .toCompletableFuture();

        try {
            records.get(5, TimeUnit.SECONDS);
            fail("the lookup should fail");
        } catch (ExecutionException e) {
            // a failed lookup of that name and type, not one of no data: a DNS error (RFC 7208 4.4)
            assertEquals(e.getCause().toString(), LookupFailedException.class, e.getCause().getClass());
            assertEquals(Name.fromString("example.com."), ((LookupFailedException) e.getCause()).getName());
            assertEquals(Type.TXT, ((LookupFailedException) e.getCause()).getType());
        }
    }

    @Test(timeout = 10000)
    public void getRecordsAsyncShouldReportADnsErrorWhenTheResolverThrows() throws Exception {
        // a resolver whose executor is shut down: it throws before it returns the stage of the query
        SimpleResolver resolver = new SimpleResolver(InetAddress.getLoopbackAddress()) {
            @Override
            public CompletionStage<Message> sendAsync(Message query, Executor executor) {
                throw new RejectedExecutionException("executor shut down");
            }
        };
        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(resolver);

        CompletableFuture<List<String>> records = dns.getRecordsAsync(new DNSRequest("example.com", DNSRequest.TXT))
            .toCompletableFuture();

        try {
            records.get(5, TimeUnit.SECONDS);
            fail("the lookup should fail");
        } catch (ExecutionException e) {
            // a failed lookup of that name and type, as for an exception of the resolver once the lookup started
            assertEquals(e.getCause().toString(), LookupFailedException.class, e.getCause().getClass());
            assertEquals(Name.fromString("example.com."), ((LookupFailedException) e.getCause()).getName());
            assertEquals(Type.TXT, ((LookupFailedException) e.getCause()).getType());
        }
    }

    @Test(timeout = 10000)
    public void getRecordsAsyncShouldEndALookupWhoseAnswerHoldsACnameOfAnotherName() throws Exception {
        AnsweringResolver resolver = new AnsweringResolver(Base64.getDecoder().decode(CNAME_OF_THE_ROOT));
        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(resolver);

        CompletableFuture<List<String>> records = dns.getRecordsAsync(new DNSRequest("example.com", DNSRequest.AAAA))
            .toCompletableFuture();

        try {
            records.get(5, TimeUnit.SECONDS);
            fail("the lookup should fail");
        } catch (ExecutionException e) {
            // a failed lookup, as for the other errors of LookupSession
            assertTrue(e.getCause().toString(), e.getCause() instanceof LookupFailedException);
        }
        // the first query, then at most one per redirect LookupSession follows
        assertTrue(resolver.getQueries() + " queries", resolver.getQueries() <= LookupSession.DEFAULT_MAX_ITERATIONS + 1);
    }

    @Test(timeout = 10000)
    public void getRecordsAsyncShouldEndALookupWhoseAnswerHoldsACnameOfAnotherClass() throws Exception {
        // NOERROR, and a CNAME of the name queried in class CH, which LookupSession neither follows nor counts
        Message message = new Message();
        message.getHeader().setFlag(Flags.QR);
        message.addRecord(new CNAMERecord(Name.fromString("example.com."), DClass.CH, 3600L,
            Name.fromString("other.example.com.")), Section.ANSWER);
        AnsweringResolver resolver = new AnsweringResolver(message.toWire());
        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(resolver);

        CompletableFuture<List<String>> records = dns.getRecordsAsync(new DNSRequest("example.com", DNSRequest.AAAA))
            .toCompletableFuture();

        try {
            records.get(5, TimeUnit.SECONDS);
            fail("the lookup should fail");
        } catch (ExecutionException e) {
            assertTrue(e.getCause().toString(), e.getCause() instanceof LookupFailedException);
        }
        // the first query, then at most one per redirect LookupSession follows
        assertTrue(resolver.getQueries() + " queries", resolver.getQueries() <= LookupSession.DEFAULT_MAX_ITERATIONS + 1);
    }

    @Test(timeout = 10000)
    public void getRecordsAsyncShouldLetLookupSessionLogTheResolverAsked() throws Exception {
        Logger logger = (Logger) LoggerFactory.getLogger(LookupSession.class);
        Level level = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.DEBUG);
        try {
            DNSServiceXBillImpl dns = new DNSServiceXBillImpl(new AnsweringResolver(Base64.getDecoder().decode(CNAME_OF_THE_ROOT)));

            dns.getRecordsAsync(new DNSRequest("example.com", DNSRequest.AAAA)).toCompletableFuture()
                .handle((records, error) -> records).get(5, TimeUnit.SECONDS);
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(level);
        }

        assertTrue(appender.list.stream()
            .anyMatch(event -> event.getFormattedMessage().startsWith("Asking AnsweringResolver for ")));
    }

}
