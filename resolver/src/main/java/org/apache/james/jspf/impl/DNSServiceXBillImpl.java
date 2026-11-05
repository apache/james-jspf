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

package org.apache.james.jspf.impl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.lookup.LookupFailedException;
import org.xbill.DNS.lookup.LookupResult;
import org.xbill.DNS.lookup.LookupSession;
import org.xbill.DNS.lookup.NoSuchRRSetException;

/**
 * This class contains helper to get all neccassary DNS infos that are needed
 * for SPF
 */
public class DNSServiceXBillImpl implements DNSService {
    private static final Logger LOGGER = LoggerFactory.getLogger(DNSServiceXBillImpl.class);

    /**
     * The queries of one asynchronous lookup: the first, then one per CNAME or DNAME followed, of
     * which LookupSession follows at most {@link LookupSession#DEFAULT_MAX_ITERATIONS}
     */
    private static final int MAX_QUERIES_PER_LOOKUP = LookupSession.DEFAULT_MAX_ITERATIONS + 1;

    /**
     * The resolver of one lookup: it fails the queries past {@link #MAX_QUERIES_PER_LOOKUP}. dnsjava
     * 3.6 LookupSession asks the same question again, without end and without counting a redirect,
     * for an answer holding a CNAME it does not follow: of another name than the one queried (with
     * an error rcode, as YXRRSET), or of another class.
     * It also fails, as Lookup does, an answer with an rcode other than NOERROR and NXDOMAIN (with its
     * extended bits, RFC 6891 6.1.3), or for another question: LookupSession would read an NXRRSET
     * answer as no record. Its {@link #send(Message)}, of the synchronous Lookup, is not bounded but
     * checks the answers the same way: Lookup reads only the 4 bits of the rcode in the header.
     * Both keep the first of several CNAME records of a name, which Message.normalize means to do.
     */
    private static final class BoundedResolver implements Resolver {
        /**
         * @return a lookup that found no record, as Lookup ends (TYPE_NOT_FOUND) on the answers that make
         *         LookupSession ask again without end
         */
        private static CompletionStage<Message> tooManyQueries(Message query) {
            LOGGER.debug("More than {} queries for {}", MAX_QUERIES_PER_LOOKUP, query.getQuestion());
            return CompletableFuture.failedFuture(new NoSuchRRSetException(query.getQuestion().getName(),
                query.getQuestion().getType()));
        }

        /**
         * @return why the answer is a DNS error (RFC 7208 4.4), or null when it is none
         */
        private static String errorOf(Message query, Message answer) {
            int rcode = answer.getRcode();
            if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN) {
                return "Answer " + Rcode.string(rcode) + " for " + query.getQuestion();
            }
            if (!query.getQuestion().equals(answer.getQuestion())) {
                return "Answer for another question than " + query.getQuestion();
            }
            return null;
        }

        /**
         * @return the records kept of an RRset of the answer: of a CNAME RRset of several records, its first
         *         CNAME record only, without the other CNAME records nor a legacy SIG record covering them,
         *         which dnsjava puts in the RRset too, and Message.normalize would take for the CNAME
         */
        private static List<Record> keptRecords(RRset rrset) {
            if (rrset.getType() != Type.CNAME || rrset.size() < 2) {
                return rrset.rrs(false);
            }
            List<Record> cname = rrset.rrs(false).stream()
                .filter(record -> record.getType() == Type.CNAME)
                .limit(1)
                .collect(Collectors.toList());
            return cname.isEmpty() ? rrset.rrs(false) : cname;
        }

        /**
         * @return the answer with only the first of several CNAME records of a name (RFC 2181 10.1 allows
         *         one), as Message.normalize means to keep: dnsjava 3.6 removes another one, the first of
         *         two, and LookupSession fails an answer of three where Lookup follows one. Such an answer
         *         is rebuilt from its RRsets, whose records have the lowest TTL of their RRset (RFC 2181 5.2)
         */
        private static Message withFirstCnames(Message answer) {
            List<RRset> rrsets = answer.getSectionRRsets(Section.ANSWER);
            if (rrsets.stream().noneMatch(rrset -> rrset.getType() == Type.CNAME && rrset.size() > 1)) {
                return answer;
            }
            Message kept = answer.clone();
            kept.removeAllRecords(Section.ANSWER);
            rrsets.forEach(rrset -> {
                keptRecords(rrset).forEach(record -> kept.addRecord(record, Section.ANSWER));
                rrset.sigs().forEach(sig -> kept.addRecord(sig, Section.ANSWER));
            });
            return kept;
        }

        /**
         * @return the answer, or a failed lookup when it is a DNS error (RFC 7208 4.4)
         */
        private static CompletionStage<Message> checked(Message query, Message answer) {
            String error = errorOf(query, answer);
            if (error != null) {
                return CompletableFuture.failedFuture(new LookupFailedException(error));
            }
            return CompletableFuture.completedFuture(withFirstCnames(answer));
        }

        private final Resolver resolver;
        private final AtomicInteger queries = new AtomicInteger();

        private BoundedResolver(Resolver resolver) {
            this.resolver = resolver;
        }

        /**
         * @see org.xbill.DNS.Resolver#setPort(int)
         */
        public void setPort(int port) {
            resolver.setPort(port);
        }

        /**
         * @see org.xbill.DNS.Resolver#setTCP(boolean)
         */
        public void setTCP(boolean flag) {
            resolver.setTCP(flag);
        }

        /**
         * @see org.xbill.DNS.Resolver#setIgnoreTruncation(boolean)
         */
        public void setIgnoreTruncation(boolean flag) {
            resolver.setIgnoreTruncation(flag);
        }

        /**
         * @see org.xbill.DNS.Resolver#setEDNS(int, int, int, List)
         */
        public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
            resolver.setEDNS(version, payloadSize, flags, options);
        }

        /**
         * @see org.xbill.DNS.Resolver#setTSIGKey(TSIG)
         */
        public void setTSIGKey(TSIG key) {
            resolver.setTSIGKey(key);
        }

        /**
         * @see org.xbill.DNS.Resolver#setTimeout(Duration)
         */
        public void setTimeout(Duration timeout) {
            resolver.setTimeout(timeout);
        }

        /**
         * @see org.xbill.DNS.Resolver#getTimeout()
         */
        public Duration getTimeout() {
            return resolver.getTimeout();
        }

        /**
         * @see org.xbill.DNS.Resolver#send(Message)
         * @throws IOException also when the answer is a DNS error: Lookup then reports TRY_AGAIN
         */
        public Message send(Message query) throws IOException {
            Message answer = resolver.send(query);
            String error = errorOf(query, answer);
            if (error != null) {
                throw new IOException(error);
            }
            return withFirstCnames(answer);
        }

        /**
         * @see org.xbill.DNS.Resolver#sendAsync(Message)
         */
        public CompletionStage<Message> sendAsync(Message query) {
            if (queries.incrementAndGet() > MAX_QUERIES_PER_LOOKUP) {
                return tooManyQueries(query);
            }
            return resolver.sendAsync(query).thenCompose(answer -> checked(query, answer));
        }

        /**
         * @see org.xbill.DNS.Resolver#sendAsync(Message, Executor)
         */
        public CompletionStage<Message> sendAsync(Message query, Executor executor) {
            if (queries.incrementAndGet() > MAX_QUERIES_PER_LOOKUP) {
                return tooManyQueries(query);
            }
            return resolver.sendAsync(query, executor).thenCompose(answer -> checked(query, answer));
        }

        /**
         * @see java.lang.Object#toString()
         */
        public String toString() {
            // the resolver asked, in the logs of LookupSession
            return resolver.toString();
        }
    }

    /**
     * @param query the lookup of the given request
     * @return the answer of the lookup
     * @throws TimeoutException on a DNS error, as dnsjava's ClassCastException on some malformed
     *         answers: DNSService declares no other exception (RFC 7208 4.4)
     */
    private static Record[] run(Lookup query, Name name, int type) throws TimeoutException {
        try {
            return query.run();
        } catch (RuntimeException e) {
            LOGGER.warn("Unexpected error of the DNS lookup of {} (type {})", name, Type.string(type), e);
            throw new TimeoutException(e.toString());
        }
    }

    /**
     * @return the failure of an asynchronous lookup, as LookupSession reports one: an unchecked exception dnsjava
     *         throws on an answer it cannot handle becomes a LookupFailedException, as getRecords reports it as
     *         a TimeoutException
     */
    private static CompletionException asLookupFailure(Throwable e, Name name, int type) {
        Throwable cause = e instanceof CompletionException && e.getCause() != null ? e.getCause() : e;
        if (cause instanceof RuntimeException && !(cause instanceof LookupFailedException)) {
            LOGGER.warn("Unexpected error of the DNS lookup of {} (type {})", name, Type.string(type), cause);
            return new CompletionException(new LookupFailedException(cause.toString(), name, type));
        }
        return e instanceof CompletionException ? (CompletionException) e : new CompletionException(e);
    }

    /**
     * @return the lookup of the name and type: an unchecked exception thrown before the stage is returned, as
     *         by a resolver whose executor is shut down (RejectedExecutionException), fails the stage instead
     */
    private static CompletionStage<LookupResult> startLookup(LookupSession session, Name name, int type) {
        try {
            return session.lookupAsync(name, type);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * @return the records of the given type: an answer can hold others
     */
    private static Record[] ofType(Record[] rr, int type) {
        if (rr == null) {
            return null;
        }
        return Arrays.stream(rr).filter(record -> record.getType() == type).toArray(Record[]::new);
    }

    // The record limit for lookups
    protected int recordLimit;

    // The resolver used for the lookup
    protected Resolver resolver;
    
    /**
     * Default Constructor.
     * Uses the DNSJava static DefaultResolver
     */
    public DNSServiceXBillImpl() {
        this(Lookup.getDefaultResolver());
    }
    
    /**
     * Constructor to specify a custom resolver.
     */
    public DNSServiceXBillImpl(Resolver resolver) {
        this.resolver = resolver;
        // Default record limit is 10
        this.recordLimit = 10;
    }

    /**
     * NOTE if this class is created with the default constructor it
     * will use the static DefaultResolver from DNSJava and this method
     * will change it's timeout.
     * Other tools using DNSJava in the same JVM could be affected by
     * this timeout change.
     * 
     * @see org.apache.james.jspf.core.DNSService#setTimeOut(int)
     */
    public synchronized void setTimeOut(int timeOut) {
        this.resolver.setTimeout(timeOut);
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getLocalDomainNames()
     */
    public List<String> getLocalDomainNames() {
        List<String> names = new ArrayList<String>();

        LOGGER.debug("Start Local ipaddress lookup");
        try {
            InetAddress ia[] = InetAddress.getAllByName(InetAddress
                    .getLocalHost().getHostName());

            for (int i = 0; i < ia.length; i++) {
                String host = ia[i].getHostName();
                names.add(host);

                LOGGER.debug("Add hostname {} to list", host);
            }
        } catch (UnknownHostException e) {
            // just ignore this..
        }
        return names;

    }

    /**
     * @return the current record limit
     */
    public int getRecordLimit() {
        return recordLimit;
    }

    /**
     * Set a new limit for the number of records for MX and PTR lookups.
     * @param recordLimit
     */
    public void setRecordLimit(int recordLimit) {
        this.recordLimit = recordLimit;
    }
    
    /**
     * @see org.apache.james.jspf.core.DNSService#getRecords(org.apache.james.jspf.core.DNSRequest)
     */
    public List<String> getRecords(DNSRequest request)
            throws TimeoutException {
        String recordTypeDescription;
        int dnsJavaType;
        switch (request.getRecordType()) {
            case DNSRequest.A: recordTypeDescription = "A"; dnsJavaType = Type.A; break;
            case DNSRequest.AAAA: recordTypeDescription = "AAAA"; dnsJavaType = Type.AAAA; break;
            case DNSRequest.MX: recordTypeDescription = "MX"; dnsJavaType = Type.MX; break;
            case DNSRequest.PTR: recordTypeDescription = "PTR"; dnsJavaType = Type.PTR; break;
            case DNSRequest.TXT: recordTypeDescription = "TXT"; dnsJavaType = Type.TXT; break;
            case DNSRequest.SPF: recordTypeDescription= "SPF"; dnsJavaType = Type.SPF; break;
            default: // TODO fail!
                return null;
        }
        try {

            LOGGER.debug("Start {}-Record lookup for : {}", recordTypeDescription, request.getHostname());

            // RFC 7208 4.3: a fully qualified name, not looked up under the search path of the host
            Name name = Name.fromString(request.getHostname(), Name.root);
            Lookup query = new Lookup(name, dnsJavaType);
            query.setResolver(new BoundedResolver(resolver));

            Record[] rr = run(query, name, dnsJavaType);
            int queryResult = query.getResult();
            

            if (queryResult == Lookup.TRY_AGAIN) {
                throw new TimeoutException(query.getErrorString());
            }
            
            List<String> records = convertRecordsToList(ofType(rr, dnsJavaType));
            
            LOGGER.debug("Found {} {}-Records", (rr != null ? rr.length : 0), recordTypeDescription);
            return records;
        } catch (TextParseException e) {
            // i think this is the best we could do
            LOGGER.debug("No {} Record found for host: {}", recordTypeDescription, request.getHostname());
            return null;
        }
    }

    @Override
    public CompletionStage<List<String>> getRecordsAsync(DNSRequest request) {
        String recordTypeDescription;
        int dnsJavaType;
        switch (request.getRecordType()) {
            case DNSRequest.A: recordTypeDescription = "A"; dnsJavaType = Type.A; break;
            case DNSRequest.AAAA: recordTypeDescription = "AAAA"; dnsJavaType = Type.AAAA; break;
            case DNSRequest.MX: recordTypeDescription = "MX"; dnsJavaType = Type.MX; break;
            case DNSRequest.PTR: recordTypeDescription = "PTR"; dnsJavaType = Type.PTR; break;
            case DNSRequest.TXT: recordTypeDescription = "TXT"; dnsJavaType = Type.TXT; break;
            case DNSRequest.SPF: recordTypeDescription= "SPF"; dnsJavaType = Type.SPF; break;
            default: // TODO fail!
                throw new IllegalArgumentException();
        }
        LOGGER.debug("Start {}-Record lookup for : {}", recordTypeDescription, request.getHostname());
        final LookupSession lookupSession = LookupSession.defaultBuilder().resolver(new BoundedResolver(this.resolver)).build();

        try {
            Name name = Name.fromString(request.getHostname(), Name.root);
            return startLookup(lookupSession, name, dnsJavaType)
                .thenApply(result -> convertRecordsToList(ofType(result.getRecords().toArray(new Record[0]), dnsJavaType)))
                .exceptionally(e -> {
                    throw asLookupFailure(e, name, dnsJavaType);
                });
        } catch (TextParseException e) {
            // no record, as getRecords answers
            LOGGER.debug("No {} Record found for host: {}", recordTypeDescription, request.getHostname());
            return CompletableFuture.completedFuture(null);
        }
    }

    /**
     * Convert the given Record array to a List
     * 
     * @param rr Record array
     * @return list
     */
    @SuppressWarnings("unchecked")
	public static List<String> convertRecordsToList(Record[] rr) {
        List<String> records;
        if (rr != null && rr.length > 0) {
            records = new ArrayList<String>();
            for (int i = 0; i < rr.length; i++) {
                // a record without data (dnsjava's EmptyRecord) has the type of the record it stands for,
                // not its class: as a record of another type, it makes no data
                if (!(rr[i] instanceof ARecord || rr[i] instanceof AAAARecord || rr[i] instanceof MXRecord
                        || rr[i] instanceof PTRRecord || rr[i] instanceof TXTRecord || rr[i] instanceof SPFRecord)) {
                    return null;
                }
                switch (rr[i].getType()) {
                    case Type.A:
                        ARecord a = (ARecord) rr[i];
                        records.add(a.getAddress().getHostAddress());
                        break;
                    case Type.AAAA:
                        AAAARecord aaaa = (AAAARecord) rr[i];
                        records.add(aaaa.getAddress().getHostAddress());
                        break;
                    case Type.MX:
                        MXRecord mx = (MXRecord) rr[i];
                        records.add(mx.getTarget().toString());
                        break;
                    case Type.PTR:
                        PTRRecord ptr = (PTRRecord) rr[i];
                        records.add(IPAddr.stripDot(ptr.getTarget().toString()));
                        break;
                    case Type.TXT:
                        TXTRecord txt = (TXTRecord) rr[i];
                        if (txt.getStrings().size() == 1) {
                            records.add((String)txt.getStrings().get(0));
                        } else {
                            StringBuffer sb = new StringBuffer();
                            for (Iterator<String> it = txt.getStrings().iterator(); it
                                    .hasNext();) {
                                String k = (String) it.next();
                                sb.append(k);
                            }
                            records.add(sb.toString());
                        }
                        break;
                    case Type.SPF:
                        SPFRecord spf = (SPFRecord) rr[i];
                        if (spf.getStrings().size() == 1) {
                            records.add((String)spf.getStrings().get(0));
                        } else {
                            StringBuffer sb = new StringBuffer();
                            for (Iterator<String> it = spf.getStrings().iterator(); it
                                    .hasNext();) {
                                String k = (String) it.next();
                                sb.append(k);
                            }
                            records.add(sb.toString());
                        }
                        break;
                    default:
                        return null;
                }
            }
        } else {
            records = null;
        }
        return records;
    }
}
