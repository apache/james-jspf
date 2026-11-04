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
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.junit.Test;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.DClass;
import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.lookup.LookupFailedException;
import org.xbill.DNS.lookup.LookupSession;

import java.io.IOException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class DNSServiceXBillImplTest {
    // rcode YXRRSET, and the answer ". CNAME .": a CNAME of the root, not of the name queried
    private static final String CNAME_OF_THE_ROOT = "AAGBJwABAAEAAAAAAAABAAHADAAFAAEAAA4QAAEA";

    // answers every query, on the calling thread, with the given message, its ID and question set to the query's
    private static final class AnsweringResolver implements Resolver {
        private final byte[] answer;
        private final AtomicInteger queries = new AtomicInteger();

        private AnsweringResolver(byte[] answer) {
            this.answer = answer;
        }

        @Override
        public void setPort(int port) {
        }

        @Override
        public void setTCP(boolean flag) {
        }

        @Override
        public void setIgnoreTruncation(boolean flag) {
        }

        @Override
        public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
        }

        @Override
        public void setTSIGKey(TSIG key) {
        }

        @Override
        public void setTimeout(Duration timeout) {
        }

        @Override
        public Message send(Message query) throws IOException {
            queries.incrementAndGet();
            Message response = new Message(answer);
            response.getHeader().setID(query.getHeader().getID());
            response.removeAllRecords(Section.QUESTION);
            response.addRecord(query.getQuestion(), Section.QUESTION);
            return response;
        }

        @Override
        public CompletionStage<Message> sendAsync(Message query) {
            try {
                return CompletableFuture.completedFuture(send(query));
            } catch (IOException e) {
                return CompletableFuture.failedFuture(e);
            }
        }

        @Override
        public CompletionStage<Message> sendAsync(Message query, Executor executor) {
            return sendAsync(query);
        }

        @Override
        public String toString() {
            return "AnsweringResolver";
        }
    }

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
        assertTrue(resolver.queries.get() + " queries", resolver.queries.get() <= LookupSession.DEFAULT_MAX_ITERATIONS + 1);
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
