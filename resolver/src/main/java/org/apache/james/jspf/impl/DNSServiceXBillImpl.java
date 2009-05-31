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

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * This class contains helper to get all neccassary DNS infos that are needed
 * for SPF
 */
public class DNSServiceXBillImpl implements DNSService {

    // The logger
    protected Logger log;
    
    // The record limit for lookups
    protected int recordLimit;

    // The resolver used for the lookup
    protected Resolver resolver;
    
    /**
     * Default Constructor.
     * Uses the DNSJava static DefaultResolver
     */
    public DNSServiceXBillImpl(Logger logger) {
        this(logger, Lookup.getDefaultResolver());
    }
    
    /**
     * Constructor to specify a custom resolver.
     */
    public DNSServiceXBillImpl(Logger logger, Resolver resolver) {
        this.log = logger;
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
    public List getLocalDomainNames() {
        List names = new ArrayList();

        log.debug("Start Local ipaddress lookup");
        try {
            InetAddress ia[] = InetAddress.getAllByName(InetAddress
                    .getLocalHost().getHostName());

            for (int i = 0; i < ia.length; i++) {
                String host = ia[i].getHostName();
                names.add(host);

                log.debug("Add hostname " + host + " to list");
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
    public List getRecords(DNSRequest request)
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

            log.debug("Start "+recordTypeDescription+"-Record lookup for : " + request.getHostname());

            Lookup query = new Lookup(request.getHostname(), dnsJavaType);
            query.setResolver(resolver);

            Record[] rr = query.run();
            int queryResult = query.getResult();
            

            if (queryResult == Lookup.TRY_AGAIN) {
                throw new TimeoutException(query.getErrorString());
            }
            
            List records = convertRecordsToList(rr);
            
            log.debug("Found " + (rr != null ? rr.length : 0) + " "+recordTypeDescription+"-Records");
            return records;
        } catch (TextParseException e) {
            // i think this is the best we could do
            log.debug("No "+recordTypeDescription+" Record found for host: " + request.getHostname());
            return null;
        }
    }
    
    /**
     * Convert the given Record array to a List
     * 
     * @param rr Record array
     * @return list
     */
    public static List convertRecordsToList(Record[] rr) {
        List records;
        if (rr != null && rr.length > 0) {
            records = new ArrayList();
            for (int i = 0; i < rr.length; i++) {
                System.out.println(rr[i].getType());
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
                            records.add(txt.getStrings().get(0));
                        } else {
                            StringBuffer sb = new StringBuffer();
                            for (Iterator it = txt.getStrings().iterator(); it
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
                            records.add(spf.getStrings().get(0));
                        } else {
                            StringBuffer sb = new StringBuffer();
                            for (Iterator it = spf.getStrings().iterator(); it
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
