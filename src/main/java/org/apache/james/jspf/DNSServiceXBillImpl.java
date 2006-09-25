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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

/**
 * This class contains helper to get all neccassary DNS infos that are needed
 * for SPF
 */
public class DNSServiceXBillImpl implements DNSService {

    // Set seconds after which we return and TempError
    private static int timeOut = 20;

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
     * @see org.apache.james.jspf.core.DNSService#getSpfRecord(java.lang.String,
     *      java.lang.String)
     */
    public String getSpfRecord(String hostname, String spfVersion)
            throws PermErrorException, TempErrorException {

        String returnValue = null;
        ArrayList txtR = new ArrayList();

        // do DNS lookup for TXT
        txtR = getTXTRecords(hostname);

        // process returned records
        if (!txtR.isEmpty()) {

            Iterator all = txtR.iterator();

            while (all.hasNext()) {
                String compare = all.next().toString().trim();

                // remove '"'
                compare = compare.toLowerCase().substring(1,
                        compare.length() - 1);

                if (compare.startsWith(spfVersion + " ")) {
                    if (returnValue == null) {
                        returnValue = compare;
                    } else {
                        throw new PermErrorException(
                                "More than 1 SPF record found for host: " + hostname);
                    }
                }
            }
        }
        return returnValue;
    }

    /**
     * Get an ArrayList of all TXT Records for a partical domain.
     * 
     * @param hostname
     *            The hostname for which the TXT-Records should be retrieved
     * @return TXT Records-which were found.
     * @throws NoneException
     *             if none TXT-Records were found.
     * @throws TempErrorException
     *             if the lookup result was "TRY_AGAIN"
     * @throws PermErrorException
     *             if an PermError should be returned
     */
    private ArrayList getTXTRecords(String hostname)
            throws TempErrorException {
        ArrayList txtR = new ArrayList();
        List records = getRecords(hostname, TXT);
        for (int i = 0; i < records.size(); i++) {
            String txt = (String) records.get(i);

            log.debug("Add txt " + txt + " to list");

            txtR.add(txt);
        }
        return txtR;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getARecords(java.lang.String,
     *      int)
     */
    public List getARecords(String strServer) throws PermErrorException, TempErrorException {

        ArrayList listTxtData = new ArrayList();

        if (IPAddr.isIPAddr(strServer)) {
            IPAddr ipTest = IPAddr.getAddress(strServer);
            // Address is already an IP address, so add it to list
            listTxtData.add(ipTest);
        } else {

            List records = getRecords(strServer, A);
            
            // check if the maximum lookup count is reached
            if (recordLimit > 0 && records.size() > recordLimit) throw new PermErrorException("Maximum A lookup count reached");
            
            for (int i = 0; i < records.size(); i++) {
                String a = (String) records.get(i);
                
                IPAddr ip = IPAddr.getAddress(a);

                log.debug("Add ipAddress " + ip + " to list");
                listTxtData.add(ip);
            }
        }
        return listTxtData;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getAAAARecords(java.lang.String,
     *      int)
     */
    public List getAAAARecords(String strServer)
            throws PermErrorException, TempErrorException {

        ArrayList listTxtData = new ArrayList();

        if (IPAddr.isIPAddr(strServer)) {
            IPAddr ipTest = IPAddr.getAddress(strServer);
            // Address is already an IP address, so add it to list
            listTxtData.add(ipTest);
        } else {
            List records = getRecords(strServer, AAAA);

            for (int i = 0; i < records.size(); i++) {
                String a = (String) records.get(i);

                IPAddr ip = IPAddr.getAddress(a);

                log.debug("Add ipAddress " + ip + " to list");
                listTxtData.add(ip);
            }
        }
        return listTxtData;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getTxtCatType(java.lang.String)
     */
    public String getTxtCatType(String strServer) throws TempErrorException {

        StringBuffer txtData = new StringBuffer();
        ArrayList records = getTXTRecords(strServer);

        log.debug("Convert " + records.size() + " TXT-Records to one String");

        for (int i = 0; i < records.size(); i++) {
            txtData.append(records.get(i));
        }
        return txtData.toString();
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getPTRRecords(java.lang.String)
     */
    public List getPTRRecords(String ipAddress) throws PermErrorException, TempErrorException {
        ArrayList ptrR = new ArrayList();

        // do DNS lookup for TXT
        IPAddr ip = IPAddr.getAddress(ipAddress);

        List records = getRecords(ip.getReverseIP() + ".in-addr.arpa", PTR);

        // check if the maximum lookup count is reached
        if (recordLimit > 0 && records.size() > recordLimit) throw new PermErrorException("Maximum PTR lookup count reached");
  
        for (int i = 0; i < records.size(); i++) {
            String ptr = (String) records.get(i);
            ptrR.add(ptr);
            log.debug("Add ipAddress " + ptr + " to list");
        }

        return ptrR;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getMXRecords(java.lang.String,
     *      int)
     */
    public List getMXRecords(String domainName)
            throws PermErrorException, TempErrorException {

        ArrayList mxR = null;
        List records = getRecords(domainName, MX);

        // check if the maximum lookup count is reached
        if (recordLimit > 0 && records.size() > recordLimit) throw new PermErrorException("Maximum MX lookup count reached");
  
        for (int i = 0; i < records.size(); i++) {
            String mx = (String) records.get(i);
            log.debug("Add MX-Record " + mx + " to list");

            List res = getARecords(mx);
            if (res != null) {
                if (mxR == null) {
                    mxR = new ArrayList();
                }
                mxR.addAll(res);
            }
        }
        
        return mxR;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#setTimeOut(int)
     */
    public synchronized void setTimeOut(int timeOut) {
        DNSServiceXBillImpl.timeOut = timeOut;
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
     * Retrieve dns records for the given host
     * 
     * @param hostname host to be queried
     * @param recordType the record type: MX, A, AAAA, PTR, TXT, SPF 
     * @return an array of Strings representing the records
     * @throws NoneException when no record is found or a textparse exception happen
     * @throws TempErrorException on timeout.
     */
    private List getRecords(String hostname, int recordType)
            throws TempErrorException {
        String recordTypeDescription;
        int dnsJavaType;
        switch (recordType) {
            case A: recordTypeDescription = "A"; dnsJavaType = Type.A; break;
            case AAAA: recordTypeDescription = "AAAA"; dnsJavaType = Type.AAAA; break;
            case MX: recordTypeDescription = "MX"; dnsJavaType = Type.MX; break;
            case PTR: recordTypeDescription = "PTR"; dnsJavaType = Type.PTR; break;
            case TXT: recordTypeDescription = "TXT"; dnsJavaType = Type.TXT; break;
            // case SPF: recordTypeDescString = "SPF"; dnsJavaType = Type.SPF; break;
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
                throw new TempErrorException("DNS Server returns RCODE: "
                        + queryResult);
            }
            
            if (rr.length > 0) {
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
                        default:
                            return null;
                    }
                    records.add(res);
                }
            } else {
                records = null;
            }
            
            log.debug("Found " + rr.length + " "+recordTypeDescription+"-Records");
        } catch (TextParseException e) {
            // i think this is the best we could do
            log.debug("No "+recordTypeDescription+" Record found for host: " + hostname);
            records = null;
        }
        return records;
    }

}
