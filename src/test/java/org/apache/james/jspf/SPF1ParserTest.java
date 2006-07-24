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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.util.regex.Pattern;

import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.parser.SPF1Parser;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class SPF1ParserTest extends TestCase {

    public SPF1ParserTest(String name) throws IOException {
        super(name);
        List tests = loadTests();
        Iterator i = tests.iterator();
        while (i.hasNext()) {
            SPF1RecordTestDef def = (SPF1RecordTestDef) i.next();
            if (name.equals(def.recIn)) {
                data = def;
                break;
            }
        }
        assertNotNull(data);
        parser = new SPF1Parser(new ConsoleLogger());
    }

    public static Test suite() throws IOException {
        return new SPF1RecordTestSuite();
    }

    private SPF1RecordTestDef data;

    private SPF1Parser parser;

    public SPF1ParserTest(SPF1RecordTestDef def, SPF1Parser parser) {
        super(def.recIn);
        this.data = def;
        this.parser = parser;
    }

    protected void runTest() throws Throwable {

        try {

            System.out.println("testing [" + data.recIn + "]");

            parser.parse(data.recIn);

            assertEquals("Expected <" + data.errMsg + "> but was <"
                    + "no errors" + ">", data.errMsg, "no errors");
        } catch (NoneException e) {
            e.printStackTrace();
            assertNotNull(data.errMsg);
            assertTrue("Expected <" + data.errMsg + "> but was <"
                    + e.getMessage() + ">", !"no errors".equals(data.errMsg));
            // assertEquals("Expected <" + data.errMsg + "> but was <"
            // + e.getMessage() + ">", data.errMsg, e.getMessage());
        } catch (PermErrorException e) {
            e.printStackTrace();
            assertNotNull(data.errMsg);
            assertTrue("Expected <" + data.errMsg + "> but was <"
                    + e.getMessage() + ">\n" + data.recOut + "\n"
                    + data.recOutAuto, !"no errors".equals(data.errMsg));
            // assertEquals("Expected <" + data.errMsg + "> but was <"
            // + e.getMessage() + ">", data.errMsg, e.getMessage());
        }

    }

    public static List loadTests() throws IOException {
        List tests = new ArrayList();

        BufferedReader br = new BufferedReader(new InputStreamReader(Thread
                .currentThread().getContextClassLoader().getResourceAsStream(
                        "org/apache/james/jspf/test_parser.txt")));

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
                            tests.add(def);
                        }
                        def = new SPF1RecordTestDef();
                        def.name = tokens[2];
                    } else if ("/.*/".equals(tokens[1])
                            || "jspf".equals(tokens[1])) {

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
            tests.add(def);
        }

        br.close();

        return tests;
    }

    static class SPF1RecordTestSuite extends TestSuite {

        public SPF1RecordTestSuite() throws IOException {
            super();
            List tests = loadTests();
            Iterator i = tests.iterator();
            SPF1Parser parser = new SPF1Parser(new ConsoleLogger());
            while (i.hasNext()) {
                addTest(new SPF1ParserTest((SPF1RecordTestDef) i.next(), parser));
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
