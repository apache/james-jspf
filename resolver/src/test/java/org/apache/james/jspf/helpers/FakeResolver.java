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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.DClass;
import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.Zone;

import java.io.IOException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * A resolver implementation to be used in unit tests.
 */
public final class FakeResolver implements Resolver {
    private static final Logger LOGGER = LoggerFactory.getLogger(FakeResolver.class);

    private static final String MSG_SEARCH_EXT = "Searching '{}' externally";
    private static final String MSG_FOUND_INT = "Found '{}' internally";

    private final List<Record> responseRecords = new ArrayList<>();
    private final Resolver externalResolver;

    /**
     * Creates an instances with a custom external resolver
     *
     * @param externalResolver a dnsjava {@link Resolver} to be used for external names
     */
    public FakeResolver(Resolver externalResolver) {
        this.externalResolver = externalResolver;
    }

    /**
     * Creates an instance with a {@link SimpleResolver}
     *
     * @throws UnknownHostException Failure occurred while finding the host
     */
    public FakeResolver() throws UnknownHostException {
        this.externalResolver = new SimpleResolver();
    }

    @Override
    public void setPort(int i) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public void setTCP(boolean b) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public void setIgnoreTruncation(boolean b) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public void setEDNS(int i, int i1, int i2, List<EDNSOption> list) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public void setTSIGKey(TSIG tsig) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public void setTimeout(Duration duration) {
        throw new UnsupportedOperationException("not implemented");
    }

    /**
     * Sends a query using the external resolver if not found internally
     *
     * @param query The query to send.
     * @return the dns message
     * {@inheritDoc}
     */
    @SuppressWarnings("LoggingSimilarMessage")
    @Override
    public Message send(Message query) throws IOException {
        Message response = buildMessage(query);
        if (response.getSection(Section.ANSWER).isEmpty() && !isInternal(query.getQuestion().getName())) {
            LOGGER.debug(MSG_SEARCH_EXT, query.getQuestion().getName());
            return externalResolver.send(query);
        } else {
            LOGGER.debug(MSG_FOUND_INT, query.getQuestion().getName());
        }

        return response;
    }

    /**
     * Sends a query using the external resolver if not found internally
     *
     * @param query The query to send.
     *              {@inheritDoc}
     */
    @SuppressWarnings("LoggingSimilarMessage")
    @Override
    public CompletionStage<Message> sendAsync(Message query) {
        Message response = buildMessage(query);
        if (response.getSection(Section.ANSWER).isEmpty() && !isInternal(query.getQuestion().getName())) {
            LOGGER.debug(MSG_SEARCH_EXT, query.getQuestion().getName());
            return externalResolver.sendAsync(query);
        } else {
            LOGGER.debug(MSG_FOUND_INT, query.getQuestion().getName());
        }

        return CompletableFuture.completedFuture(response);
    }

    /**
     * Sends a query using the external resolver if not found internally
     *
     * @param query    The query to send.
     * @param executor The service to use for async operations.
     *                 {@inheritDoc}
     */
    @Override
    public CompletionStage<Message> sendAsync(Message query, Executor executor) {
        return this.sendAsync(query);
    }

    /**
     * Sends a query using the external resolver if not found internally
     * {@inheritDoc}
     */
    @Override
    @SuppressWarnings("deprecation")
    public Object sendAsync(Message query, ResolverListener listener) {
        return this.sendAsync(query);
    }

    /**
     * Tests if a name is found internally
     *
     * @param name name to test
     * @return result
     */
    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    private boolean isInternal(Name name) {
        for (Record r : responseRecords) {
            if (name.relativize(r.getName()) != name) {
                return true;
            }
        }

        return false;
    }

    /**
     * Save the records to the list. Records in the list will be used to resolve names.
     * The list is cleared before.
     *
     * @param responseRecords records
     */
    public void setRecords(List<Record> responseRecords) {
        this.responseRecords.clear();
        this.responseRecords.addAll(responseRecords);
    }

    /**
     * Save the record to the list. Records in the list will be used to resolve names.
     * The list is cleared before.
     *
     * @param responseRecord record
     */
    public void setRecord(Record responseRecord) {
        this.responseRecords.clear();
        this.responseRecords.add(responseRecord);
    }

    /**
     * Save the record to the list. Records in the list will be used to resolve names.
     * The list is NOT cleared.
     *
     * @param responseRecord record
     */
    public void addRecord(Record responseRecord) {
        this.responseRecords.add(responseRecord);
    }

    /**
     * Clear the records list;
     */
    public void clearRecords() {
        responseRecords.clear();
    }

    /**
     * Returns the records list.
     *
     * @return list
     */
    public List<Record> getRecords() {
        return responseRecords;
    }

    /**
     * Add records to the list. Records in the list will be used to resolve names.
     * The list is NOT cleared.
     *
     * @param responseRecords records
     */
    public void addRecords(List<Record> responseRecords) {
        this.responseRecords.addAll(responseRecords);
    }

    /**
     * Import records from a zone file.
     * Records list is not cleared.
     *
     * @param domain   domain name
     * @param zoneFile zonefile path
     * @throws IOException if unable to open file
     */
    public void fromZoneFile(String domain, String zoneFile) throws IOException {
        if (domain == null) {
            throw new IllegalArgumentException("Invalid domain");
        }
        if (!domain.endsWith(".")) {
            domain += ".";
        }
        Zone z = new Zone(Name.fromString(domain), zoneFile);
        for (RRset rrset : z) {
            responseRecords.addAll(rrset.rrs());
        }
    }

    /**
     * Generate N txt records with random strings.
     *
     * @param name  name
     * @param count number of records
     * @return the list of records generated
     */
    public static List<Record> genNRandomTXTRecords(String name, int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> {
                    try {
                        return genRandomTXTRecord(Name.fromString(name));
                    } catch (TextParseException e) {
                        throw new IllegalArgumentException(e);
                    }
                }).collect(Collectors.toList());
    }

    /**
     * Generate a txt record with a random string.
     *
     * @param name name
     * @return record generated
     */
    public static Record genRandomTXTRecord(Name name) {
        int first = 97; //a
        int last = 122; //z
        int nameLen = 100;
        StringBuilder sb = new StringBuilder();
        while (sb.length() < nameLen) {
            sb.append((char) ThreadLocalRandom.current().nextInt(first, last + 1));
        }
        return new TXTRecord(name, DClass.IN, 30L, sb.toString());
    }

    /**
     * Build a DNS message from the list of records from matching the query.
     *
     * @param query the dns query
     * @return the dns answer
     */
    private Message buildMessage(Message query) {
        Message response = new Message(query.getHeader().getID());
        response.addRecord(query.getQuestion(), Section.QUESTION);
        response.getHeader().setRcode(Rcode.NOERROR);
        for (Record r : responseRecords) {
            if (query.getQuestion().getName().toString().equals(r.getName().toString())
                    && (query.getQuestion().getType() == r.getType() ||
                    (query.getQuestion().getType() == Type.A && r.getType() == Type.CNAME))) {
                response.addRecord(r, Section.ANSWER);
            }
        }
        return response;
    }

    @Override
    public String toString() {
        return "FakeResolver [records=" + responseRecords.size() + "]";
    }
}
