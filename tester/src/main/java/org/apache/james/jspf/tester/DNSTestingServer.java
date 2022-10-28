/**************************************************************** 
 * This work is derived from 'jnamed.java' distributed in       *
 * 'dnsjava-2.0.5'. This original is licensed as follows:       *
 * Copyright (c) 1999-2005, Brian Wellington                    *
 * All rights reserved.                                         *
 *                                                              *
 * Redistribution and use in source and binary forms, with or   * 
 * without modification, are permitted provided that the        *  
 * following conditions are met:                                * 
 *                                                              * 
 *  * Redistributions of source code must retain the above      *
 *    copyright notice, this list of conditions and the         *
 *    following disclaimer.                                     *
 *  * Redistributions in binary form must reproduce the above   *
 *    copyright notice, this list of conditions and the         *
 *    following disclaimer in the documentation and/or other    *
 *    materials provided with the distribution.                 *
 *  * Neither the name of the dnsjava project nor the names     *
 *    of its contributors may be used to endorse or promote     *
 *    products derived from this software without specific      *
 *    prior written permission.                                 *
 *                                                              *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND       *
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,  *
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF     *
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE     *
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR         *
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, *
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,     *
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR       *
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS         *
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF            *
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT    *
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT   *
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE          *
 * POSSIBILITY OF SUCH DAMAGE.                                  *
 *                                                              *
 * Modifications are                                            * 
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

import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Address;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNAMERecord;
import org.xbill.DNS.ExtendedFlags;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.SetResponse;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
import org.xbill.DNS.Zone;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

public class DNSTestingServer implements ResponseGenerator {

    static final int FLAG_DNSSECOK = 1;

    static final int FLAG_SIGONLY = 2;

    protected Zone zone;
    
    private Set<Name> timeoutServers;
    
    Random random = new Random();

    public DNSTestingServer(String address, String porta)
            throws TextParseException, IOException {

        Integer port = new Integer(porta != null ? porta : "53");
        InetAddress addr = Address.getByAddress(address != null ? address
                : "0.0.0.0");

        Thread t;
        t = new Thread(new TCPListener(addr, port.intValue(), this));
        t.setDaemon(true);
        t.start();

        t = new Thread(new UDPListener(addr, port.intValue(), this));
        t.setDaemon(true);
        t.start();

        zone = null;
    }

    @SuppressWarnings("unchecked")
    public synchronized void setData(Map<String, List<?>> map) {
        try {
            this.timeoutServers = new HashSet<Name>();
            List<Record> records = new LinkedList<Record>();

            records.add(new SOARecord(Name.root, DClass.IN, 3600, Name.root,
                    Name.root, 857623948, 0, 0, 0, 0));
            records.add(new NSRecord(Name.root, DClass.IN, 3600, Name.root));

            Iterator<String> hosts = map.keySet().iterator();
            while (hosts.hasNext()) {
                String host = (String) hosts.next();
                Name hostname;
                if (!host.endsWith(".")) {
                    hostname = Name.fromString(host + ".");
                } else {
                    hostname = Name.fromString(host);
                }

                List<?> l = map.get(host);
                if (l != null)
                    for (Iterator<?> i = l.iterator(); i.hasNext();) {
                        Object o = i.next();
                        if (o instanceof Map) {
                            Map<String, ?> hm = (Map) o;

                            Iterator<String> types = hm.keySet().iterator();

                            while (types.hasNext()) {
                                String type = (String) types.next();
                                if ("MX".equals(type)) {
                                    List<?> mxList = (List<?>) hm.get(type);
                                    Iterator<?> mxs = mxList.iterator();
                                    while (mxs.hasNext()) {
                                        Long prio = (Long) mxs.next();
                                        String cname = (String) mxs.next();
                                        if (cname != null) {
                                            if (cname.length() > 0 &&  !cname.endsWith(".")) cname += ".";
                                            
                                            records.add(new MXRecord(hostname,
                                                    DClass.IN, 3600, prio
                                                            .intValue(), Name
                                                            .fromString(cname)));
                                        }
                                    }
                                } else {
                                    Object value = hm.get(type);
                                    if ("A".equals(type)) {
                                        records.add(new ARecord(hostname,
                                                DClass.IN, 3600, Address
                                                        .getByAddress((String) value)));
                                    } else if ("AAAA".equals(type)) {
                                        records.add(new AAAARecord(hostname,
                                                DClass.IN, 3600, Address
                                                        .getByAddress((String) value)));
                                    } else if ("SPF".equals(type)) {
                                        if (value instanceof List<?>) {
                                            records.add(new SPFRecord(hostname,
                                                    DClass.IN, 3600L, (List<String>) value));
                                        } else {
                                            records.add(new SPFRecord(hostname,
                                                    DClass.IN, 3600, (String) value));
                                        }
                                    } else if ("TXT".equals(type)) {
                                        if (value instanceof List<?>) {
                                            records.add(new TXTRecord(hostname,
                                                    DClass.IN, 3600L, (List<String>) value));
                                        } else {
                                            records.add(new TXTRecord(hostname,
                                                    DClass.IN, 3600, (String) value));
                                        }
                                    } else {
                                        if (!((String) value).endsWith(".")) {
                                            value = ((String) value)+".";
                                        }
                                        if ("PTR".equals(type)) {
                                            records
                                                    .add(new PTRRecord(
                                                            hostname,
                                                            DClass.IN,
                                                            3600,
                                                            Name
                                                                    .fromString((String) value)));
                                        } else if ("CNAME".equals(type)) {
                                            records.add(new CNAMERecord(
                                                    hostname, DClass.IN, 3600,
                                                    Name.fromString((String) value)));
                                        } else {
                                            throw new IllegalStateException(
                                                    "Unsupported type: " + type);
                                        }
                                    }
                                }
                            }
                        } else if ("TIMEOUT".equals(o)) {
                            timeoutServers.add(hostname);
                        } else {
                            throw new IllegalStateException(
                                    "getRecord found an unexpected data");
                        }
                    }
            }

            zone = new Zone(Name.root, (Record[]) records
                    .toArray(new Record[] {}));
            
        } catch (TextParseException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private SOARecord findSOARecord() {
        return zone.getSOA();
    }

    private RRset findNSRecords() {
        return zone.getNS();
    }

    // TODO verify why enabling this lookup will make some test to fail!
    private RRset findARecord(Name name) {
        return null;
        //return zone.findExactMatch(name, Type.A);
    }

    private SetResponse findRecords(Name name, int type) {
        SetResponse sr = zone.findRecords(name, type);
        
        if (sr == null || sr.answers() == null || sr.answers().size() == 0) {
            boolean timeout = timeoutServers.contains(name);
            if (timeout) {
                try {
                    Thread.sleep(2100);
                }
                catch (InterruptedException e) {
                }
                return null;
            }
        }
        
        try {
            Thread.sleep(random.nextInt(500));
        }
        catch (Exception e) {} 
        
        return sr;
    }

    @SuppressWarnings("unchecked")
    void addRRset(Name name, Message response, RRset rrset, int section,
            int flags) {
        for (int s = 1; s <= section; s++)
            if (response.findRRset(name, rrset.getType(), s))
                return;
        if ((flags & FLAG_SIGONLY) == 0) {
            Iterator<Record> it = rrset.rrs().iterator();
            while (it.hasNext()) {
                Record r = (Record) it.next();
                if (r.getName().isWild() && !name.isWild())
                    r = r.withName(name);
                response.addRecord(r, section);
            }
        }
        if ((flags & (FLAG_SIGONLY | FLAG_DNSSECOK)) != 0) {
            Iterator it = rrset.sigs().iterator();
            while (it.hasNext()) {
                Record r = (Record) it.next();
                if (r.getName().isWild() && !name.isWild())
                    r = r.withName(name);
                response.addRecord(r, section);
            }
        }
    }

    private void addGlue(Message response, Name name, int flags) {
        RRset a = findARecord(name);
        if (a == null)
            return;
        addRRset(name, response, a, Section.ADDITIONAL, flags);
    }

    private void addAdditional2(Message response, int section, int flags) {
        Record[] records = response.getSectionArray(section);
        for (int i = 0; i < records.length; i++) {
            Record r = records[i];
            Name glueName = r.getAdditionalName();
            if (glueName != null)
                addGlue(response, glueName, flags);
        }
    }

    private final void addAdditional(Message response, int flags) {
        addAdditional2(response, Section.ANSWER, flags);
        addAdditional2(response, Section.AUTHORITY, flags);
    }

    byte addAnswer(Message response, Name name, int type, int dclass,
            int iterations, int flags) {
        SetResponse sr;
        byte rcode = Rcode.NOERROR;

        if (iterations > 6)
            return Rcode.NOERROR;

        if (type == Type.SIG || type == Type.RRSIG) {
            type = Type.ANY;
            flags |= FLAG_SIGONLY;
        }

        sr = findRecords(name, type);

        // TIMEOUT
        if (sr == null) {
            return -1;
        }
        
        if (sr.isNXDOMAIN() || sr.isNXRRSET()) {
            if (sr.isNXDOMAIN())
                response.getHeader().setRcode(Rcode.NXDOMAIN);

            response.addRecord(findSOARecord(), Section.AUTHORITY);

            if (iterations == 0)
                response.getHeader().setFlag(Flags.AA);

            rcode = Rcode.NXDOMAIN;

        } else if (sr.isDelegation()) {
            RRset nsRecords = sr.getNS();
            addRRset(nsRecords.getName(), response, nsRecords,
                    Section.AUTHORITY, flags);
        } else if (sr.isCNAME()) {
            CNAMERecord cname = sr.getCNAME();
            RRset rrset = new RRset(cname);
            addRRset(name, response, rrset, Section.ANSWER, flags);
            if (iterations == 0)
                response.getHeader().setFlag(Flags.AA);
            rcode = addAnswer(response, cname.getTarget(), type, dclass,
                    iterations + 1, flags);
        } else if (sr.isDNAME()) {
            DNAMERecord dname = sr.getDNAME();
            RRset rrset = new RRset(dname);
            addRRset(name, response, rrset, Section.ANSWER, flags);
            Name newname;
            try {
                newname = name.fromDNAME(dname);
            } catch (NameTooLongException e) {
                return Rcode.YXDOMAIN;
            }
            rrset = new RRset(new CNAMERecord(name, dclass, 0, newname));
            addRRset(name, response, rrset, Section.ANSWER, flags);
            if (iterations == 0)
                response.getHeader().setFlag(Flags.AA);
            rcode = addAnswer(response, newname, type, dclass, iterations + 1,
                    flags);
        } else if (sr.isSuccessful()) {
            List<RRset> rrsets = sr.answers();
            for (int i = 0; i < rrsets.size(); i++)
                addRRset(name, response, rrsets.get(i), Section.ANSWER, flags);

            RRset findNSRecords = findNSRecords();
            addRRset(findNSRecords.getName(), response, findNSRecords,
                    Section.AUTHORITY, flags);

            if (iterations == 0)
                response.getHeader().setFlag(Flags.AA);
        }
        return rcode;
    }

    public byte[] generateReply(Message query, int length, Socket s)
            throws IOException {
        Header header;
        int maxLength;
        int flags = 0;

        header = query.getHeader();
        if (header.getFlag(Flags.QR))
            return null;
        if (header.getRcode() != Rcode.NOERROR)
            return errorMessage(query, Rcode.FORMERR);
        if (header.getOpcode() != Opcode.QUERY)
            return errorMessage(query, Rcode.NOTIMP);

        Record queryRecord = query.getQuestion();

        OPTRecord queryOPT = query.getOPT();
        if (queryOPT != null && queryOPT.getVersion() > 0) {
        }

        if (s != null)
            maxLength = 65535;
        else if (queryOPT != null)
            maxLength = Math.max(queryOPT.getPayloadSize(), 512);
        else
            maxLength = 512;

        if (queryOPT != null && (queryOPT.getFlags() & ExtendedFlags.DO) != 0)
            flags = FLAG_DNSSECOK;

        Message response = new Message(query.getHeader().getID());
        response.getHeader().setFlag(Flags.QR);
        if (query.getHeader().getFlag(Flags.RD))
            response.getHeader().setFlag(Flags.RD);
        response.addRecord(queryRecord, Section.QUESTION);

        Name name = queryRecord.getName();
        int type = queryRecord.getType();
        int dclass = queryRecord.getDClass();
        if (!Type.isRR(type) && type != Type.ANY)
            return errorMessage(query, Rcode.NOTIMP);

        byte rcode = addAnswer(response, name, type, dclass, 0, flags);
        
        // TIMEOUT
        if (rcode == -1) {
            return null;
        }
        
        if (rcode != Rcode.NOERROR && rcode != Rcode.NXDOMAIN)
            return errorMessage(query, rcode);

        addAdditional(response, flags);

        if (queryOPT != null) {
            int optflags = (flags == FLAG_DNSSECOK) ? ExtendedFlags.DO : 0;
            OPTRecord opt = new OPTRecord((short) 4096, rcode, (byte) 0,
                    optflags);
            response.addRecord(opt, Section.ADDITIONAL);
        }

        return response.toWire(maxLength);
    }

    byte[] buildErrorMessage(Header header, int rcode, Record question) {
        Message response = new Message();
        response.setHeader(header);
        for (int i = 0; i < 4; i++)
            response.removeAllRecords(i);
        if (rcode == Rcode.SERVFAIL)
            response.addRecord(question, Section.QUESTION);
        header.setRcode(rcode);
        return response.toWire();
    }

    public byte[] formerrMessage(byte[] in) {
        Header header;
        try {
            header = new Header(in);
        } catch (IOException e) {
            return null;
        }
        return buildErrorMessage(header, Rcode.FORMERR, null);
    }

    public byte[] errorMessage(Message query, int rcode) {
        return buildErrorMessage(query.getHeader(), rcode, query.getQuestion());
    }

    public byte[] generateReply(byte[] in, int length) {
        Message query;
        byte[] response = null;
        try {
            query = new Message(in);
            response = generateReply(query, length, null);
        } catch (IOException e) {
            response = formerrMessage(in);
        }
        return response;
    }

}
