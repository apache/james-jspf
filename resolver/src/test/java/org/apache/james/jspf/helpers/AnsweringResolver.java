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

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;

/**
 * Answers every query, on the calling thread, with the same message, its ID and question set to
 * the query's: a DNS server giving an unusual answer.
 */
public final class AnsweringResolver implements Resolver {
    /**
     * @param rcode an rcode
     * @return a resolver answering every query with that rcode and no record
     */
    public static AnsweringResolver withRcode(int rcode) {
        Message answer = new Message();
        answer.getHeader().setFlag(Flags.QR);
        answer.getHeader().setRcode(rcode);
        return new AnsweringResolver(answer.toWire());
    }

    /**
     * @return a resolver failing every query with an I/O error other than a time out
     */
    public static AnsweringResolver unreachable() {
        return new AnsweringResolver(null);
    }

    private final byte[] answer;
    private final AtomicInteger queries = new AtomicInteger();

    /**
     * @param answer the message, in wire format
     */
    public AnsweringResolver(byte[] answer) {
        this.answer = answer;
    }

    /**
     * @return the number of queries received
     */
    public int getQueries() {
        return queries.get();
    }

    /**
     * @see org.xbill.DNS.Resolver#setPort(int)
     */
    @Override
    public void setPort(int port) {
    }

    /**
     * @see org.xbill.DNS.Resolver#setTCP(boolean)
     */
    @Override
    public void setTCP(boolean flag) {
    }

    /**
     * @see org.xbill.DNS.Resolver#setIgnoreTruncation(boolean)
     */
    @Override
    public void setIgnoreTruncation(boolean flag) {
    }

    /**
     * @see org.xbill.DNS.Resolver#setEDNS(int, int, int, List)
     */
    @Override
    public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
    }

    /**
     * @see org.xbill.DNS.Resolver#setTSIGKey(TSIG)
     */
    @Override
    public void setTSIGKey(TSIG key) {
    }

    /**
     * @see org.xbill.DNS.Resolver#setTimeout(Duration)
     */
    @Override
    public void setTimeout(Duration timeout) {
    }

    /**
     * @see org.xbill.DNS.Resolver#send(Message)
     */
    @Override
    public Message send(Message query) throws IOException {
        queries.incrementAndGet();
        if (answer == null) {
            throw new IOException("Network is unreachable");
        }
        Message response = new Message(answer);
        response.getHeader().setID(query.getHeader().getID());
        response.removeAllRecords(Section.QUESTION);
        response.addRecord(query.getQuestion(), Section.QUESTION);
        return response;
    }

    /**
     * @see org.xbill.DNS.Resolver#sendAsync(Message)
     */
    @Override
    public CompletionStage<Message> sendAsync(Message query) {
        try {
            return CompletableFuture.completedFuture(send(query));
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * @see org.xbill.DNS.Resolver#sendAsync(Message, Executor)
     */
    @Override
    public CompletionStage<Message> sendAsync(Message query, Executor executor) {
        return sendAsync(query);
    }

    /**
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "AnsweringResolver";
    }
}
