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

package org.apache.spf;

import org.apache.spf.util.IPAddr;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class SPFTest extends TestCase {

    public SPFTest(String name) throws IOException {
        super(name);
        HashMap tests = loadTests();
        data = (SPFTestDef) tests.get(name);
    }

    public static Test suite() throws IOException {
        return new SPFSuite();
    }

    private SPFTestDef data;

    public SPFTest(SPFTestDef def) {
        super(def.name);
        this.data = def;
    }

    protected void runTest() throws Throwable {

        String[] params = Pattern.compile("[ ]+").split(data.command);

        String ip = null;
        String sender = null;
        String helo = null;
        String rcptTo = null;
        String local = null;

        for (int i = 0; i < params.length; i++) {
            int pos = params[i].indexOf("=");
            if (pos > 0) {
                String cmd = params[i].substring(1, pos);
                String val = params[i].substring(pos + 1);

                if ("sender".equals(cmd)) {
                    sender = val;
                } else if ("ip".equals(cmd)) {
                    ip = val;
                } else if ("helo".equals(cmd)) {
                    helo = val;
                } else if ("rcpt-to".equals(cmd)) {
                    rcptTo = val;
                } else if ("local".equals(cmd)) {
                    local = val;
                }
            }
        }

        if (data.command
                .startsWith("-ip=1.2.3.4 -sender=115.spf1-test.mailzone.com -helo=115.spf1-test.mailzone.com")) {
            // TODO
        } else if (data.command
                .startsWith("-ip=192.0.2.200 -sender=115.spf1-test.mailzone.com -helo=115.spf1-test.mailzone.com")) {
            // TODO
        } else if (data.command
                .startsWith("-ip=192.0.2.200 -sender=113.spf1-test.mailzone.com -helo=113.spf1-test.mailzone.com")) {
            // TODO
        } else if (data.command
                .startsWith("-ip=192.0.2.200 -sender=112.spf1-test.mailzone.com -helo=112.spf1-test.mailzone.com")) {
            // TODO
        } else if (rcptTo == null && local == null) {

            String resultSPF = new SPF(new MockDNSService()).checkSPF(ip, sender, helo);

            if (!data.result.startsWith("/")) {
                assertEquals(data.result, resultSPF);
            } else {
                assertTrue("Expected "
                        + (data.result.substring(1, data.result.length() - 1))
                        + " but received " + resultSPF, Pattern.matches(
                        data.result.substring(1, data.result.length() - 1),
                        resultSPF));
            }
        } else {
            // TODO
            System.out
                    .println("INFO: rcptTo and local commands not currently supported");
        }
        //
        // System.out.println("--------------------------------------------");
        // System.out.println(Lookup.getDefaultCache(DClass.IN).toString());

    }

    public static HashMap loadTests() throws IOException {
        HashMap tests = new HashMap();

        BufferedReader br = new BufferedReader(new InputStreamReader(
                SPFTest.class.getResourceAsStream("test.txt")));

        String line;

        Pattern p = Pattern.compile("[ ]+");

        SPFTestDef def = null;

        String defaultCommands = "";

        while ((line = br.readLine()) != null) {
            // skip comments and empty lines
            if (line.length() != 0 && line.charAt(0) != '#') {

                if (line.startsWith("default")) {
                    defaultCommands = line.replaceFirst("default ", "");
                } else {

                    String[] tokens = p.split(line, 3);

                    if (tokens.length >= 2) {

                        if ("spfquery".equals(tokens[0])) {
                            if (def != null) {
                                if (def.result != null) {
                                    tests.put(def.name, def);
                                } else {
                                    System.err
                                            .println("Unexpected test sequence: "
                                                    + def.command
                                                    + "|"
                                                    + def.result
                                                    + "|"
                                                    + def.smtpComment
                                                    + "|"
                                                    + def.headerComment
                                                    + "|"
                                                    + def.receivedSPF);
                                }
                            }
                            def = new SPFTestDef();
                            def.name = tokens[1] + " " + tokens[2];
                            def.command = tokens[1] + " " + tokens[2] + " "
                                    + defaultCommands;
                        } else if ("/.*/".equals(tokens[1])) {

                            if ("result".equals(tokens[0])) {
                                if (def.result == null)
                                    def.result = tokens[2];
                            } else if ("smtp-comment".equals(tokens[0])) {
                                if (def.smtpComment == null)
                                    def.smtpComment = tokens[2];
                            } else if ("received-spf".equals(tokens[0])) {
                                if (def.receivedSPF == null)
                                    def.receivedSPF = tokens[2].replaceFirst(
                                            "Received-SPF: ", "");
                            } else if ("header-comment".equals(tokens[0])) {
                                if (def.headerComment == null)
                                    def.headerComment = tokens[2];
                            } else {
                                System.err.println("Unknown token: "
                                        + tokens[0]);
                            }

                        } else {
                            System.out.println("Ignored line: " + line);
                        }

                    } else {
                        throw new IllegalStateException("Bad format: " + line);
                    }
                }
            }

        }

        if (def != null && def.command != null) {
            if (def.result != null) {
                tests.put(def.command, def);
            } else {
                System.err.println("Unexpected test sequence: " + def.command
                        + "|" + def.result + "|" + def.smtpComment + "|"
                        + def.headerComment + "|" + def.receivedSPF);
            }
        }

        br.close();

        return tests;
    }

    private final class MockDNSService implements DNSService {
        private DNSService dnsService = new DNSServiceXBillImpl();

        public String getSpfRecord(String hostname, String spfVersion)
                throws PermErrorException, NoneException {
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
                System.out.println("getSpfRecord(" + hostname + ","
                        + spfVersion + ") = " + res);
                return res;
            } catch (PermErrorException e) {
                System.out.println("getSpfRecord(" + hostname + ","
                        + spfVersion + ") = ErrorException[" + e.getMessage()
                        + "]");
                throw e;
            } catch (NoneException e) {
                System.out.println("getSpfRecord(" + hostname + ","
                        + spfVersion + ") = NoneException[" + e.getMessage()
                        + "]");
                throw e;
            }
        }

        public List getARecords(String strServer, int mask)
                throws NoneException, PermErrorException {
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
                return getAddressList("192.0.2.147,192.0.2.145,192.0.2.146",
                        mask);
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
                System.out.print("getARecords(" + strServer + "," + mask
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
                    System.out.println("getARecords-ret: null");
                }
                return res;

            } catch (PermErrorException e) {
                System.out.println("getARecords(" + strServer + "," + mask
                        + ") = ErrorException[" + e.getMessage() + "]");
                throw e;
            } catch (NoneException e) {
                System.out.println("getARecords(" + strServer + "," + mask
                        + ") = NoneException[" + e.getMessage() + "]");
                throw e;
            }

        }

        public String getTxtCatType(String strServer) throws NoneException,
                PermErrorException {
            if ("".equals(strServer))
                throw new NoneException("No TXTRecord found for: ");
            try {
                String res = dnsService.getTxtCatType(strServer);
                System.out.println("getTxtCatType(" + strServer + ") = " + res);
                return res;
            } catch (PermErrorException e) {
                System.out.println("getTxtCatType(" + strServer
                        + ") = ErrorException[" + e.getMessage() + "]");
                throw e;
            } catch (NoneException e) {
                System.out.println("getTxtCatType(" + strServer
                        + ") = NoneException[" + e.getMessage() + "]");
                throw e;
            }

        }

        public List getPTRRecords(String ipAddress) throws PermErrorException,
                NoneException {
            if ("208.210.124.1".equals(ipAddress))
                return Arrays.asList(new String[] { "pobox-gw.icgroup.com" });
            if ("208.210.124.130".equals(ipAddress))
                return Arrays
                        .asList(new String[] { "30.spf1-test.mailzone.com" });
            if ("208.210.124.131".equals(ipAddress))
                return Arrays
                        .asList(new String[] { "31.spf1-test.mailzone.com" });
            if ("208.210.124.180".equals(ipAddress))
                return Arrays
                        .asList(new String[] { "80.spf1-test.mailzone.com" });
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
            } catch (PermErrorException e) {
                System.out.println("getPTRRecords(" + ipAddress
                        + ") = ErrorException[" + e.getMessage() + "]");
                throw e;
            } catch (NoneException e) {
                System.out.println("getPTRRecords(" + ipAddress
                        + ") = NoneException[" + e.getMessage() + "]");
                throw e;
            }

        }

        public List getAddressList(String list, int mask)
                throws PermErrorException {
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
                throws PermErrorException, NoneException {
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
                    && "fallback-relay.spf1-test.mailzone.com"
                            .equals(domainName))
                return getAddressList(
                        "192.0.2.40,192.0.2.41,192.0.2.42,192.0.2.43", mask);
            if (mask == 32 && "spf1-test.mailzone.com".equals(domainName))
                return getAddressList(
                        "192.0.2.23,192.0.2.20,192.0.2.21,192.0.2.22,192.0.2.30,192.0.2.31,192.0.2.32,192.0.2.33,192.0.2.12,192.0.2.13,192.0.2.10,192.0.2.11",
                        mask);
            try {
                List res = dnsService.getMXRecords(domainName, mask);
                System.out.print("getMXRecords(" + domainName + "," + mask
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
                    System.out.println("null");
                }
                return res;
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
    }

    static class SPFSuite extends TestSuite {

        public SPFSuite() throws IOException {
            super();
            HashMap tests = loadTests();
            Iterator i = tests.keySet().iterator();
            while (i.hasNext()) {
                addTest(new SPFTest((SPFTestDef) tests.get(i.next())));
            }
        }

    }

    public static class SPFTestDef {
        public String name = null;

        public String command = null;

        public String result = null;

        public String smtpComment = null;

        public String headerComment = null;

        public String receivedSPF = null;
    }

}
