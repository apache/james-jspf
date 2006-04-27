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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Pattern;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class SPF1ParserTest extends TestCase {

    public SPF1ParserTest(String name) throws IOException {
        super(name);
        HashMap tests = loadTests();
        data = (SPF1RecordTestDef) tests.get(name);
        assertNotNull(data);
    }

    public static Test suite() throws IOException {
        return new SPF1RecordTestSuite();
    }

    private SPF1RecordTestDef data;

    public SPF1ParserTest(SPF1RecordTestDef def) {
        super(def.recIn);
        this.data = def;
    }

    protected void runTest() throws Throwable {
        String mailFrom = "byteaction.de";
        String ipAddress = "192.168.0.100";
        String helo = "byteaction.de";

        try {
            SPF1Data d = new SPF1Data(mailFrom, helo, ipAddress);
            SPF1Parser r = new SPF1Parser(data.recIn, d);
            
            assertEquals("Expected <" + data.errMsg + "> but was <"
                    + "no errors" + ">", data.errMsg, "no errors");
        } catch (NoneException e) {
            assertNotNull(data.errMsg);
            assertTrue("Expected <" + data.errMsg + "> but was <"
                    + e.getMessage() + ">",!"no errors".equals(data.errMsg));
//            assertEquals("Expected <" + data.errMsg + "> but was <"
//                    + e.getMessage() + ">", data.errMsg, e.getMessage());
        } catch (ErrorException e) {
            assertNotNull(data.errMsg);
            assertTrue("Expected <" + data.errMsg + "> but was <"
                  + e.getMessage() + ">",!"no errors".equals(data.errMsg));
//            assertEquals("Expected <" + data.errMsg + "> but was <"
//                    + e.getMessage() + ">", data.errMsg, e.getMessage());
        }

    }

    public static HashMap loadTests() throws IOException {
        HashMap tests = new HashMap();

        BufferedReader br = new BufferedReader(new InputStreamReader(
                SPF1ParserTest.class.getResourceAsStream("test_parser.txt")));

        String line;

        Pattern p = Pattern.compile("[ ]+");

        SPF1RecordTestDef def = null;

        while ((line = br.readLine()) != null) {
            // skip comments and empty lines
            if (line.length() != 0 && line.charAt(0) != '#') {
                String[] tokens = p.split(line, 3);

                if (tokens.length >= 2) {

                    if ("spftest".equals(tokens[0])) {
                        if (def != null && def.recIn != null) {
                            tests.put(def.recIn, def);
                        }
                        def = new SPF1RecordTestDef();
                        def.name = tokens[2];
                    } else if ("/.*/".equals(tokens[1])
                            || "spfjava".equals(tokens[1])) {

                        if ("rec-in".equals(tokens[0])) {
                            if (def.recIn == null)
                                def.recIn = tokens[2].replaceFirst(
                                        "SPF record in:  ", "");
                        } else if ("err-msg".equals(tokens[0])) {
                            if (def.errMsg == null)
                                def.errMsg = tokens[2];
                        } else if ("rec-out".equals(tokens[0])) {
                            if (def.recOut == null)
                                def.recOut = tokens[2].replaceFirst(
                                        "SPF record:  ", "");
                        } else if ("rec-out-auto".equals(tokens[0])) {
                            if (tokens.length == 3) {
                                if (def.recOutAuto == null)
                                    def.recOutAuto = tokens[2];
                            } else {
                                if (def.recOutAuto == null)
                                    def.recOutAuto = "";
                            }
                        } else {
                            System.err.println("Unknown token: " + tokens[0]);
                        }

                    } else {
                        System.err
                                .println("Ignored line for different implementation: "
                                        + tokens[1]);
                    }

                } else {
                    throw new IllegalStateException("Bad format: " + line);
                }
            }

        }

        if (def != null && def.recIn != null) {
            tests.put(def.recIn, def);
        }

        br.close();

        return tests;
    }

    static class SPF1RecordTestSuite extends TestSuite {

        public SPF1RecordTestSuite() throws IOException {
            super();
            HashMap tests = loadTests();
            Iterator i = tests.keySet().iterator();
            while (i.hasNext()) {
                addTest(new SPF1ParserTest((SPF1RecordTestDef) tests.get(i
                        .next())));
            }
        }

    }

    public static class SPF1RecordTestDef {
        public String name = null;

        public String recIn = null;

        public String errMsg = null;

        public String recOutAuto = null;

        public String recOut = null;
    }

}
