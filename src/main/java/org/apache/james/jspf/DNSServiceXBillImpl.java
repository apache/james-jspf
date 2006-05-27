/***********************************************************************
 * Copyright (c) 2006 The Apache Software Foundation.             *
 * All rights reserved.                                                *
 * ------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License"); you *
 * may not use this file except in compliance with the License. You    *
 * may obtain a copy of the License at:                                *
 *                                                                     *
 *     http://www.apache.org/licenses/LICENSE-2.0                      *
 *                                                                     *
 * Unless required by applicable law or agreed to in writing, software *
 * distributed under the License is distributed on an "AS IS" BASIS,   *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or     *
 * implied.  See the License for the specific language governing       *
 * permissions and limitations under the License.                      *
 ***********************************************************************/

package org.apache.james.jspf;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.log4j.Logger;
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
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 * 
 */

public class DNSServiceXBillImpl implements DNSService {

    // Set seconds after which we return and TempError
    private static int timeOut = 20;

    private static Logger log = Logger.getLogger(DNSServiceXBillImpl.class);

    /**
     * @see org.apache.james.jspf.core.DNSService#getSpfRecord(java.lang.String,
     *      java.lang.String)
     */
    public String getSpfRecord(String hostname, String spfVersion)
            throws PermErrorException, NoneException, TempErrorException {

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
                                "More than 1 SPF record found");
                    }
                }
            }
        }
        if (returnValue == null) {
            throw new NoneException("No SPF record found");
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
    private static ArrayList getTXTRecords(String hostname)
            throws NoneException, TempErrorException {
        ArrayList txtR = new ArrayList();
        Record[] records;
        try {

            log.debug("Start TXT-Record lookup for : " + hostname);

            Lookup.getDefaultResolver().setTimeout(timeOut);
            Lookup query = new Lookup(hostname, Type.TXT);
            records = query.run();
            int queryResult = query.getResult();
            if ((queryResult != Lookup.TRY_AGAIN)) {
                if (records != null) {

                    log.debug("Found " + records.length + " TXT-Records");

                    for (int i = 0; i < records.length; i++) {
                        TXTRecord txt = (TXTRecord) records[i];

                        log
                                .debug("Add txt " + txt.rdataToString()
                                        + " to list");

                        txtR.add(txt.rdataToString());
                    }
                } else {
                    throw new NoneException("No TXTRecord found for: "
                            + hostname);
                }
            } else {
                throw new TempErrorException("DNS Server returns RCODE: "
                        + queryResult);
            }
        } catch (TextParseException e) {
            // I think thats the best we could do
            throw new NoneException("No TXTRecord found for: " + hostname);
        }
        return txtR;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getARecords(java.lang.String,
     *      int)
     */
    public List getARecords(String strServer, int mask) throws NoneException,
            PermErrorException, TempErrorException {

        ArrayList listTxtData = new ArrayList();

        if (IPAddr.isIPAddr(strServer)) {
            IPAddr ipTest = IPAddr.getAddress(strServer);
            // Address is already an IP address, so add it to list
            listTxtData.add(ipTest);
        } else {

            Record[] records;
            try {

                log.debug("Start A-Record lookup for : " + strServer);

                Lookup.getDefaultResolver().setTimeout(timeOut);
                Lookup query = new Lookup(strServer, Type.A);
                records = query.run();
                int queryResult = query.getResult();

                if ((queryResult != Lookup.TRY_AGAIN)) {
                    if (records != null) {

                        log.debug("Found " + records.length + " A-Records");

                        for (int i = 0; i < records.length; i++) {
                            ARecord a = (ARecord) records[i];

                            ArrayList ipArray = getIPList(a.getAddress()
                                    .getHostAddress(), mask);
                            Iterator ip = ipArray.iterator();

                            while (ip.hasNext()) {
                                Object ipA = ip.next();

                                log.debug("Add ipAddress " + ipA + " to list");
                                listTxtData.add(ipA);
                            }
                        }
                    } else {
                        throw new NoneException("No A record found for: "
                                + strServer);
                    }
                } else {
                    throw new TempErrorException("DNS Server returns RCODE: "
                            + queryResult);
                }
            } catch (TextParseException e) {
                // i think this is the best we could do
                throw new NoneException("No A Record found for: " + strServer);
            }
        }
        return listTxtData;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getAAAARecords(java.lang.String,
     *      int)
     */
    public List getAAAARecords(String strServer, int mask)
            throws NoneException, PermErrorException, TempErrorException {

        ArrayList listTxtData = new ArrayList();

        if (IPAddr.isIPAddr(strServer)) {
            IPAddr ipTest = IPAddr.getAddress(strServer);
            // Address is already an IP address, so add it to list
            listTxtData.add(ipTest);
        } else {

            Record[] records;
            try {

                log.debug("Start AAAA-Record lookup for : " + strServer);

                Lookup.getDefaultResolver().setTimeout(timeOut);
                Lookup query = new Lookup(strServer, Type.AAAA);
                records = query.run();
                int queryResult = query.getResult();

                if ((queryResult != Lookup.TRY_AGAIN)) {
                    if (records != null) {

                        log.debug("Found " + records.length + " AAAA-Records");

                        for (int i = 0; i < records.length; i++) {
                            AAAARecord a = (AAAARecord) records[i];

                            ArrayList ipArray = getIPList(a.getAddress()
                                    .getHostAddress(), mask);
                            Iterator ip = ipArray.iterator();

                            while (ip.hasNext()) {
                                Object ipA = ip.next();

                                log.debug("Add ipAddress " + ipA + " to list");
                                listTxtData.add(ipA);
                            }
                        }
                    } else {
                        throw new NoneException("No AAAA record found for: "
                                + strServer);
                    }
                } else {
                    throw new TempErrorException("DNS Server returns RCODE: "
                            + queryResult);
                }
            } catch (TextParseException e) {
                // i think this is the best we could do
                throw new NoneException("No AAAA Record found for: "
                        + strServer);
            }
        }
        return listTxtData;
    }

    /**
     * Convert list of DNS names to masked IPAddr
     * 
     * @param addressList
     *            ArrayList of DNS names which should be converted to masked
     *            IPAddresses
     * @param maskLength
     *            the networkmask
     * @return ArrayList of the conversion
     * @throws PermErrorException
     *             if an PermError should be returned
     */
    private ArrayList getAList(ArrayList addressList, int maskLength)
            throws PermErrorException {

        ArrayList listAddresses = new ArrayList();
        String aValue;

        for (int i = 0; i < addressList.size(); i++) {
            aValue = addressList.get(i).toString();
            try {
                listAddresses.addAll(getARecords(aValue, maskLength));
            } catch (Exception e) {
                // Carry on regardless?
            }
        }
        return listAddresses;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getTxtCatType(java.lang.String)
     */
    public String getTxtCatType(String strServer) throws NoneException,
            TempErrorException {

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
    public List getPTRRecords(String ipAddress) throws NoneException,
            PermErrorException, TempErrorException {

        ArrayList ptrR = new ArrayList();
        Record[] records;

        // do DNS lookup for TXT
        IPAddr ip;

        ip = IPAddr.getAddress(ipAddress);

        try {

            log.debug("Start PTR-Record lookup for : " + ipAddress);

            Lookup.getDefaultResolver().setTimeout(timeOut);
            Lookup query = new Lookup(ip.getReverseIP() + ".in-addr.arpa",
                    Type.PTR);
            records = query.run();
            int queryResult = query.getResult();

            if ((queryResult != Lookup.TRY_AGAIN)) {
                if (records != null) {
                    log.debug("Found " + records.length + " PTR-Records");

                    for (int i = 0; i < records.length; i++) {
                        PTRRecord ptr = (PTRRecord) records[i];
                        ptrR.add(IPAddr.stripDot(ptr.getTarget().toString()));
                        log.debug("Add ipAddress "
                                + IPAddr.stripDot(ptr.getTarget().toString())
                                + " to list");
                    }
                } else {
                    throw new NoneException("No PTRRecord found for: "
                            + ipAddress);
                }
            } else {
                throw new TempErrorException("DNS Server returns RCODE: "
                        + queryResult);
            }
        } catch (TextParseException e) {
            // i think this is the best we could do
            throw new NoneException("No PTRRecord found for: " + ipAddress);
        }

        return ptrR;
    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getMXRecords(java.lang.String,
     *      int)
     */
    public List getMXRecords(String domainName, int mask)
            throws PermErrorException, NoneException, TempErrorException {

        ArrayList mxAddresses = getAList(getMXNames(domainName), mask);
        return mxAddresses;

    }

    /**
     * Get an ArrayList of IPAddr's given the DNS type and mask
     * 
     * @param host
     *            The hostname or ip of the server for which we want to get the
     *            ips
     * @param mask
     *            The netmask
     * @return ipAddresses Array which contains all ipAddresses
     */
    private static ArrayList getIPList(String host, int mask)
            throws PermErrorException {

        ArrayList listIP = new ArrayList();

        try {
            if (host != null) {
                listIP.addAll(IPAddr.getAddresses(host, mask));
            }
        } catch (Exception e1) {
            throw new PermErrorException(e1.getMessage());
        }

        return listIP;

    }

    /**
     * Get all MX Records for a domain
     * 
     * @param host
     *            The hostname we want to retrieve the MXRecords for
     * @return MX-Records for the given hostname
     * @throws NoneException
     *             if no MX-Records was found
     * @throws TempErrorException
     *             if the lookup result was "TRY_AGAIN"
     */
    private static ArrayList getMXNames(String host) throws NoneException,
            TempErrorException {
        ArrayList mxR = new ArrayList();
        Record[] records;
        try {

            log.debug("Start MX-Record lookup for : " + host);

            Lookup.getDefaultResolver().setTimeout(timeOut);
            Lookup query = new Lookup(host, Type.MX);

            records = query.run();
            int queryResult = query.getResult();

            if ((queryResult != Lookup.TRY_AGAIN)) {
                if (records != null) {
                    log.debug("Found " + records.length + " MX-Records");

                    for (int i = 0; i < records.length; i++) {
                        MXRecord mx = (MXRecord) records[i];
                        log.debug("Add MX-Record " + mx.getTarget()
                                + " to list");

                        mxR.add(mx.getTarget());

                    }
                } else {
                    throw new NoneException("No MX Record found for: " + host);
                }
            } else {
                throw new TempErrorException("DNS Server returns RCODE: "
                        + queryResult);
            }
        } catch (TextParseException e) {
            // i think this is the best we could do
            throw new NoneException("No MX Record found for: " + host);
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
}
