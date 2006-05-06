/***********************************************************************
 * Copyright (c) 2006-2006 The Apache Software Foundation.             *
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

import org.apache.james.jspf.DNSServiceXBillImpl;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class SPF1TestMockDNSService implements DNSService {

    /**
     * @param suite
     */
    public SPF1TestMockDNSService() {
    }

    private DNSService dnsService = new DNSServiceXBillImpl();

    public String getSpfRecord(String hostname, String spfVersion)
            throws PermErrorException, NoneException, TempErrorException {
        if ("v=spf1".equals(spfVersion)) {
            if ("01.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1                                                             ";
            if ("02.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1                                             -all       ";
            if ("03.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1                                             ~all";
            if ("05.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1                                             default=deny   ";
            if ("06.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1                                             ?all ";
            if ("07.spf1-test.mailzone.com".equals(hostname))
                throw new NoneException("No SPF record found");
            if ("08.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1                       -all      ?all  ";
            if ("09.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1    scope=header-from scope=envelope         -all  ";
            if ("10.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 mx                                          -all";
            if ("100.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1      redirect=98.spf1-test.mailzone.com";
            if ("101.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 -all redirect=98.spf1-test.mailzone.com";
            if ("102.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 ?all redirect=98.spf1-test.mailzone.com";
            if ("103.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1      redirect=98.%{d3}";
            if ("104.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1      redirect=105.%{d3}";
            if ("105.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1      redirect=106.%{d3}";
            if ("106.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1      redirect=107.%{d3}org.apache.spf.IncludeException: loop encountered";
            if ("107.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1       include:104.%{d3}";
            if ("11.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1    mx:spf1-test.mailzone.com                          -all";
            if ("110.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 some:unrecognized=mechanism some=unrecognized:modifier -all";
            if ("111.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 mx -a gpg ~all exp=111txt.spf1-test.mailzone.com";
            if ("112.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 a mp3 ~all";
            if ("113.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 a mp3: ~all";
            if ("114.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 mx -a gpg=test ~all exp=114txt.spf1-test.mailzone.com";
            if ("115.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 a mp3=yes -all";
            if ("116.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 redirect=116rdr.spf1-test.mailzone.com a";
            if ("116rdr.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 -all";
            if ("117.spf1-test.mailzone.com".equals(hostname))
                throw new NoneException("No SPF record found");
            if ("118.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 -all exp=";
            if ("12.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 mx mx:spf1-test.mailzone.com                          -all";
            if ("13.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1    mx:spf1-test.mailzone.com mx:fallback-relay.spf1-test.mailzone.com -all";
            if ("14.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 mx mx:spf1-test.mailzone.com mx:fallback-relay.spf1-test.mailzone.com -all";
            if ("20.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 a                                           -all";
            if ("21.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1   a:spf1-test.mailzone.com                            -all";
            if ("22.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 a a:spf1-test.mailzone.com                            -all";
            if ("30.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 ptr                                         -all";
            if ("31.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1     ptr:spf1-test.mailzone.com                        -all";
            if ("32.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 ptr ptr:spf1-test.mailzone.com                        -all";
            if ("40.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 exists:%{ir}.%{v}._spf.%{d}                    -all";
            if ("41.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 exists:%{ir}.%{v}._spf.spf1-test.mailzone.com            -all";
            if ("42.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 exists:%{ir}.%{v}._spf.%{d} exists:%{ir}.%{v}._spf.%{d3} -all";
            if ("45.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 -a a:spf1-test.mailzone.com                           -all";
            if ("50.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 include                                     -all";
            if ("51.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 include:42.spf1-test.mailzone.com                  -all";
            if ("52.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 include:53.spf1-test.mailzone.com                  -all";
            if ("53.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 include:42.spf1-test.mailzone.com                  -all";
            if ("55.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 include:56.spf1-test.mailzone.com                  -all";
            if ("56.spf1-test.mailzone.com".equals(hostname))
                throw new NoneException(
                        "No TXTRecord found for: 56.spf1-test.mailzone.com");
            if ("57.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 include:spf1-test.mailzone.com         -all";
            if ("58.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 include:59.spf1-test.mailzone.com                  -all";
            if ("59.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 include:58.spf1-test.mailzone.com                  -all";
            if ("70.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 exists:%{lr+=}.lp._spf.spf1-test.mailzone.com -all";
            if ("80.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 a mx exists:%{ir}.%{v}._spf.80.spf1-test.mailzone.com ptr -all";
            if ("90.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1  ip4:192.0.2.128/25 -all";
            if ("91.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 -ip4:192.0.2.128/25 ip4:192.0.2.0/24 -all";
            if ("92.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 ?ip4:192.0.2.192/26 ip4:192.0.2.128/25 -ip4:192.0.2.0/24 -all";
            if ("95.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 exists:%{p}.whitelist.spf1-test.mailzone.com -all";
            if ("96.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 -exists:%{d}.blacklist.spf1-test.mailzone.com -all";
            if ("97.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 exists:%{p}.whitelist.spf1-test.mailzone.com -exists:%{d}.blacklist.spf1-test.mailzone.com -all";
            if ("98.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 a/26 mx/26 -all";
            if ("99.spf1-test.mailzone.com".equals(hostname))
                return "v=spf1 -all exp=99txt.spf1-test.mailzone.com moo";
            if ("localhost".equals(hostname))
                throw new NoneException("No TXTRecord found for: localhost");
            if ("spf1-test.mailzone.com".equals(hostname))
                throw new NoneException(
                        "No TXTRecord found for: spf1-test.mailzone.com");
        }
        try {
            String res = dnsService.getSpfRecord(hostname, spfVersion);
            System.out.println("getSpfRecord(" + hostname + "," + spfVersion
                    + ") = " + res);
            return res;
        } catch (TempErrorException e) {
            System.out.println("getSpfRecord(" + hostname + "," + spfVersion
                    + ") = TempErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getSpfRecord(" + hostname + "," + spfVersion
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getSpfRecord(" + hostname + "," + spfVersion
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }
    }

    public List getLocalDomainNames() {
        List res = dnsService.getLocalDomainNames();
        System.out.print("getLocalDomainNames() = ");
        if (res != null) {
            for (int i = 0; i < res.size(); i++) {
                System.out.print(res.get(i));
                if (i == res.size() - 1) {
                    System.out.println("");
                } else {
                    System.out.print(",");
                }
            }
        } else {
            System.out.println("getLocalDomainNames-ret: null");
        }
        return res;

    }

    public List getAAAARecords(String strServer, int mask)
            throws NoneException, PermErrorException, TempErrorException {

        try {
            List res = dnsService.getAAAARecords(strServer, mask);
            System.out.print("getAAAARecords(" + strServer + "," + mask
                    + ") = ");
            if (res != null) {
                for (int i = 0; i < res.size(); i++) {
                    System.out.print(res.get(i));
                    if (i == res.size() - 1) {
                        System.out.println("");
                    } else {
                        System.out.print(",");
                    }
                }
            } else {
                System.out.println("getAAAARecords-ret: null");
            }
            return res;

        } catch (TempErrorException e) {
            System.out.println("getAAAARecords(" + strServer + "," + mask
                    + ") = TermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getAAAARecords(" + strServer + "," + mask
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getAAAARecords(" + strServer + "," + mask
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }
    }

    public List getARecords(String strServer, int mask) throws NoneException,
            PermErrorException, TempErrorException {
        if (mask == 32
                && "1.bob.lp._spf.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "1.joe.lp._spf.spf1-test.mailzone.com".equals(strServer))
            throw new NoneException(
                    "No A record found for: 1.joe.lp._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "100.2.0.192.in-addr._spf.40.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "100.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 100.2.0.192.in-addr._spf.42.spf1-test.mailzone.com");
        if (mask == 32
                && "100.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 100.2.0.192.in-addr._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "100.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 100.2.0.192.in-addr._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "101.2.0.192.in-addr._spf.40.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "102.2.0.192.in-addr._spf.40.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 102.2.0.192.in-addr._spf.40.spf1-test.mailzone.com");
        if (mask == 32
                && "110.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 110.2.0.192.in-addr._spf.42.spf1-test.mailzone.com");
        if (mask == 32
                && "110.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "111.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32 && "111.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.200", mask);
        if (mask == 32 && "112.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.200", mask);
        if (mask == 32 && "113.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.200", mask);
        if (mask == 32 && "114.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.200", mask);
        if (mask == 32 && "115.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.200", mask);
        if (mask == 32 && "116.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.200", mask);
        if (mask == 32
                && "130.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "131.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "2.bob.lp._spf.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32 && "20.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.120", mask);
        if (mask == 32
                && "200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "200.2.0.192.in-addr._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 200.2.0.192.in-addr._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "208.210.124.1.whitelist.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 208.210.124.1.whitelist.spf1-test.mailzone.com");
        if (mask == 32
                && "208.210.124.180.whitelist.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 208.210.124.180.whitelist.spf1-test.mailzone.com");
        if (mask == 32
                && "208.210.124.180.whitelist.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 208.210.124.180.whitelist.spf1-test.mailzone.com");
        if (mask == 32 && "22.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.122", mask);
        if (mask == 32 && "30.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("208.210.124.130", mask);
        if (mask == 32 && "31.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("208.210.124.131", mask);
        if (mask == 32
                && "4.24.236.64.in-addr._spf.80.spf1-test.mailzone.com"
                        .equals(strServer))
            throw new NoneException(
                    "No A record found for: 4.24.236.64.in-addr._spf.80.spf1-test.mailzone.com");
        if (mask == 32 && "45.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.147,192.0.2.145,192.0.2.146", mask);
        if (mask == 32 && "80.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("208.210.124.180", mask);
        if (mask == 32
                && "80.spf1-test.mailzone.com.whitelist.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "80.2.0.192.in-addr._spf.80.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "96.spf1-test.mailzone.com.blacklist.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "97.spf1-test.mailzone.com.blacklist.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 26 && "98.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("192.0.2.98", mask);
        if (mask == 32
                && "bob.lp._spf.spf1-test.mailzone.com".equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32
                && "droid.lp._spf.spf1-test.mailzone.com".equals(strServer))
            throw new NoneException(
                    "No A record found for: droid.lp._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "joe-2.lp._spf.spf1-test.mailzone.com".equals(strServer))
            throw new NoneException(
                    "No A record found for: joe-2.lp._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "moe-1.lp._spf.spf1-test.mailzone.com".equals(strServer))
            throw new NoneException(
                    "No A record found for: moe-1.lp._spf.spf1-test.mailzone.com");
        if (mask == 32
                && "postmaster.lp._spf.spf1-test.mailzone.com"
                        .equals(strServer))
            return getAddressList("127.0.0.2", mask);
        if (mask == 32 && "spf1-test.mailzone.com".equals(strServer))
            return getAddressList("208.210.124.192,192.0.2.200", mask);
        if (mask == 32 && "www1.cnn.com".equals(strServer))
            return getAddressList("64.236.24.4", mask);

        try {
            List res = dnsService.getARecords(strServer, mask);
            System.out.print("getARecords(" + strServer + "," + mask + ") = ");
            if (res != null) {
                for (int i = 0; i < res.size(); i++) {
                    System.out.print(res.get(i));
                    if (i == res.size() - 1) {
                        System.out.println("");
                    } else {
                        System.out.print(",");
                    }
                }
            } else {
                System.out.println("getARecords-ret: null");
            }
            return res;

        } catch (TempErrorException e) {
            System.out.println("getARecords(" + strServer + "," + mask
                    + ") = TermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getARecords(" + strServer + "," + mask
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getARecords(" + strServer + "," + mask
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }

    }

    public String getTxtCatType(String strServer) throws NoneException,
            PermErrorException, TempErrorException {
        if ("".equals(strServer))
            throw new NoneException("No TXTRecord found for: ");
        try {
            String res = dnsService.getTxtCatType(strServer);
            System.out.println("getTxtCatType(" + strServer + ") = " + res);
            return res;
        } catch (TempErrorException e) {
            System.out.println("getTxtCatType(" + strServer
                    + ") = TempErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getTxtCatType(" + strServer
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getTxtCatType(" + strServer
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }

    }

    public List getPTRRecords(String ipAddress) throws PermErrorException,
            NoneException, TempErrorException {
        if ("208.210.124.1".equals(ipAddress))
            return Arrays.asList(new String[] { "pobox-gw.icgroup.com" });
        if ("208.210.124.130".equals(ipAddress))
            return Arrays.asList(new String[] { "30.spf1-test.mailzone.com" });
        if ("208.210.124.131".equals(ipAddress))
            return Arrays.asList(new String[] { "31.spf1-test.mailzone.com" });
        if ("208.210.124.180".equals(ipAddress))
            return Arrays.asList(new String[] { "80.spf1-test.mailzone.com" });
        if ("208.210.124.192".equals(ipAddress))
            return Arrays.asList(new String[] { "spf1-test.mailzone.com" });
        if ("64.236.24.4".equals(ipAddress))
            return Arrays.asList(new String[] { "www1.cnn.com" });
        try {
            List res = dnsService.getPTRRecords(ipAddress);
            System.out.print("getPTRRecords(" + ipAddress + ") = ");
            if (res != null) {
                for (int i = 0; i < res.size(); i++) {
                    System.out.print(res.get(i));
                    if (i == res.size() - 1) {
                        System.out.println("");
                    } else {
                        System.out.print(",");
                    }
                }
            } else {
                System.out.println("null");
            }
            return res;
        } catch (TempErrorException e) {
            System.out.println("getPTRRecords(" + ipAddress
                    + ") = TempErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getPTRRecords(" + ipAddress
                    + ") = PermErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getPTRRecords(" + ipAddress
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }

    }

    public List getAddressList(String list, int mask) throws PermErrorException {
        if (list == null || "".equals(list)) {
            return new ArrayList();
        }
        String[] s = list.split(",");
        IPAddr[] ips = new IPAddr[s.length];
        for (int i = 0; i < s.length; i++) {
            ips[i] = IPAddr.getAddress(s[i], mask);
        }
        return new ArrayList(Arrays.asList(ips));
    }

    public List getMXRecords(String domainName, int mask)
            throws PermErrorException, NoneException, TempErrorException {
        if (mask == 32 && "10.spf1-test.mailzone.com".equals(domainName))
            return getAddressList(
                    "192.0.2.23,192.0.2.20,192.0.2.21,192.0.2.22,192.0.2.30,192.0.2.31,192.0.2.32,192.0.2.33,192.0.2.12,192.0.2.13,192.0.2.10,192.0.2.11",
                    mask);
        if (mask == 32 && "12.spf1-test.mailzone.com".equals(domainName))
            return getAddressList(
                    "192.0.2.23,192.0.2.20,192.0.2.21,192.0.2.22,192.0.2.30,192.0.2.31,192.0.2.32,192.0.2.33,192.0.2.12,192.0.2.13,192.0.2.10,192.0.2.11",
                    mask);
        if (mask == 32 && "14.spf1-test.mailzone.com".equals(domainName))
            return getAddressList(
                    "192.0.2.23,192.0.2.20,192.0.2.21,192.0.2.22,192.0.2.30,192.0.2.31,192.0.2.32,192.0.2.33,192.0.2.12,192.0.2.13,192.0.2.10,192.0.2.11",
                    mask);
        if (mask == 32 && "111.spf1-test.mailzone.com".equals(domainName))
            return getAddressList(
                    "192.0.2.12,192.0.2.13,192.0.2.10,192.0.2.11", mask);
        if (mask == 32 && "114.spf1-test.mailzone.com".equals(domainName))
            return getAddressList(
                    "192.0.2.11,192.0.2.12,192.0.2.13,192.0.2.10", mask);
        if (mask == 32 && "80.spf1-test.mailzone.com".equals(domainName))
            throw new NoneException(
                    "No MX Record found for: 80.spf1-test.mailzone.com");
        if (mask == 26 && "98.spf1-test.mailzone.com".equals(domainName))
            return getAddressList("208.210.124.180", mask);
        if (mask == 32
                && "fallback-relay.spf1-test.mailzone.com".equals(domainName))
            return getAddressList(
                    "192.0.2.40,192.0.2.41,192.0.2.42,192.0.2.43", mask);
        if (mask == 32 && "spf1-test.mailzone.com".equals(domainName))
            return getAddressList(
                    "192.0.2.23,192.0.2.20,192.0.2.21,192.0.2.22,192.0.2.30,192.0.2.31,192.0.2.32,192.0.2.33,192.0.2.12,192.0.2.13,192.0.2.10,192.0.2.11",
                    mask);
        try {
            List res = dnsService.getMXRecords(domainName, mask);
            System.out
                    .print("getMXRecords(" + domainName + "," + mask + ") = ");
            if (res != null) {
                for (int i = 0; i < res.size(); i++) {
                    System.out.print(res.get(i));
                    if (i == res.size() - 1) {
                        System.out.println("");
                    } else {
                        System.out.print(",");
                    }
                }
            } else {
                System.out.println("null");
            }
            return res;
        } catch (TempErrorException e) {
            System.out.println("getMXRecords(" + domainName + "," + mask
                    + ") = TempErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (PermErrorException e) {
            System.out.println("getMXRecords(" + domainName + "," + mask
                    + ") = ErrorException[" + e.getMessage() + "]");
            throw e;
        } catch (NoneException e) {
            System.out.println("getMXRecords(" + domainName + "," + mask
                    + ") = NoneException[" + e.getMessage() + "]");
            throw e;
        }

    }

    public void setTimeOut(int timeOut) {
        // MOCK
    }
}