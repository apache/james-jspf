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

package org.apache.james.jspf.tester;

import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.util.Collections;

import static org.junit.Assert.assertEquals;

public class DNSTestingServerTest {
    /**
     * @return the answer of a server holding a TXT record of example.com to an EDNS query
     */
    private static Message answerOf(String name, int type) throws IOException {
        DNSTestingServer server = new DNSTestingServer();
        server.setData(Collections.singletonMap("example.com",
            Collections.singletonList(Collections.singletonMap("TXT", "v=spf1 -all"))));
        Message query = Message.newQuery(Record.newRecord(Name.fromString(name), type, DClass.IN));
        query.addRecord(new OPTRecord(1232, 0, 0), Section.ADDITIONAL);
        byte[] wire = query.toWire();

        return new Message(server.generateReply(wire, wire.length));
    }

    @Test(timeout = 10000)
    public void shouldAnswerNxdomainToAnEdnsQueryOfANameThatDoesNotExist() throws Exception {
        Message answer = answerOf("other.example.com.", Type.TXT);

        // the rcode is in the header, the OPT record holds no extended bits (RFC 6891 6.1.3)
        assertEquals(Rcode.NXDOMAIN, answer.getRcode());
    }

    @Test(timeout = 10000)
    public void shouldAnswerNoErrorToAnEdnsQueryOfATypeTheNameHasNot() throws Exception {
        Message answer = answerOf("example.com.", Type.A);

        assertEquals(Rcode.NOERROR, answer.getRcode());
    }
}
