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

import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.net.UnknownHostException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class DNSServiceXBillImplTest {
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

}
