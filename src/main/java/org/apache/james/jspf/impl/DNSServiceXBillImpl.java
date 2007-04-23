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

import org.apache.james.jspf.ResponseImpl;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.IResponseQueue;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.SPFRecord;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * This class contains helper to get all neccassary DNS infos that are needed
 * for SPF
 */
public class DNSServiceXBillImpl implements DNSService {

    // Set seconds after which we return and TempError
    private int timeOut = 20;

    // The logger
    private Logger log;
    
    // The record limit for lookups
    private int recordLimit;
    
    /**
     * Default Constructor
     */
    public DNSServiceXBillImpl(Logger logger) {
        this.log = logger;
        // Default record limit is 10
        this.recordLimit = 10;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#setTimeOut(int)
     */
    public synchronized void setTimeOut(int timeOut) {
        this.timeOut = timeOut;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getLocalDomainNames();
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
     * @see org.apache.james.jspf.core.DNSService#getRecords(java.lang.String, int)
     */
    public List getRecords(String hostname, int recordType)
            throws TimeoutException {
        String recordTypeDescription;
        int dnsJavaType;
        int recordCount = 0;
        switch (recordType) {
            case A: recordTypeDescription = "A"; dnsJavaType = Type.A; break;
            case AAAA: recordTypeDescription = "AAAA"; dnsJavaType = Type.AAAA; break;
            case MX: recordTypeDescription = "MX"; dnsJavaType = Type.MX; break;
            case PTR: recordTypeDescription = "PTR"; dnsJavaType = Type.PTR; break;
            case TXT: recordTypeDescription = "TXT"; dnsJavaType = Type.TXT; break;
            case SPF: recordTypeDescription= "SPF"; dnsJavaType = Type.SPF; break;
            default: // TODO fail!
                return null;
        }
        List records;
        try {

            log.debug("Start "+recordTypeDescription+"-Record lookup for : " + hostname);

            Lookup.getDefaultResolver().setTimeout(timeOut);
            Lookup query = new Lookup(hostname, dnsJavaType);

            Record[] rr = query.run();
            int queryResult = query.getResult();

            if (queryResult == Lookup.TRY_AGAIN) {
                throw new TimeoutException();
            }
            
            if (rr != null && rr.length > 0) {
                records = new ArrayList();
                for (int i = 0; i < rr.length; i++) {
                    String res;
                    switch (recordType) {
                        case A:
                            ARecord a = (ARecord) rr[i];
                            res = a.getAddress().getHostAddress();
                            break;
                        case AAAA:
                            AAAARecord aaaa = (AAAARecord) rr[i];
                            res = aaaa.getAddress().getHostAddress();
                            break;
                        case MX:
                            MXRecord mx = (MXRecord) rr[i];
                            res = mx.getTarget().toString();
                            break;
                        case PTR:
                            PTRRecord ptr = (PTRRecord) rr[i];
                            res = IPAddr.stripDot(ptr.getTarget().toString());
                            break;
                        case TXT:
                            TXTRecord txt = (TXTRecord) rr[i];
                            res = txt.rdataToString();
                            break;
                        case SPF:
                            SPFRecord spf = (SPFRecord) rr[i];
                            res = spf.rdataToString();
                            break;
                        default:
                            return null;
                    }
                    records.add(res);
                }
                recordCount = rr.length;
            } else {
                records = null;
            }
            
            log.debug("Found " + recordCount + " "+recordTypeDescription+"-Records");
        } catch (TextParseException e) {
            // i think this is the best we could do
            log.debug("No "+recordTypeDescription+" Record found for host: " + hostname);
            records = null;
        }
        return records;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getRecordsAsynch(java.lang.String, int, java.lang.Object, org.apache.james.jspf.core.IResponseQueue)
     */
    public void getRecordsAsynch(String hostname, int recordType, Object id,
            IResponseQueue responsePool) {
        try {
            responsePool.insertResponse(new ResponseImpl(id, getRecords(hostname, recordType)));
        } catch (TimeoutException e) {
            responsePool.insertResponse(new ResponseImpl(id, e));
        }

    }

}
