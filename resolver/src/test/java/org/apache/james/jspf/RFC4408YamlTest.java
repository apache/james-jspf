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

import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.impl.Log4JLogger;
import org.apache.james.jspf.tester.SPFYamlTestDescriptor;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestSuite;
import junit.textui.TestRunner;

public class RFC4408YamlTest extends AbstractYamlTest {

    private static final String YAMLFILE2 = "rfc4408-tests-2009.10.yml";

    /**
     * @param name
     * @throws IOException
     */
    public RFC4408YamlTest(String name) throws IOException {
        super(name);
    }

    protected RFC4408YamlTest(SPFYamlTestDescriptor def) {
        super(def);
    }

    protected RFC4408YamlTest(SPFYamlTestDescriptor def, String test) {
        super(def, test);
    }

    protected String getFilename() {
        return YAMLFILE2;
    }

    public static Test suite() throws IOException {
        return new RFC4408Suite();
    }

    static class RFC4408Suite extends TestSuite {

        public RFC4408Suite() throws IOException {
            super();
            try {
                List<SPFYamlTestDescriptor> tests = SPFYamlTestDescriptor.loadTests(YAMLFILE2);
                Iterator<SPFYamlTestDescriptor> i = tests.iterator();
                while (i.hasNext()) {
                    SPFYamlTestDescriptor o = i.next();
                    Iterator<String> ttt = o.getTests().keySet().iterator();
                    while (ttt.hasNext()) {
                        addTest(new RFC4408YamlTest(o, ttt.next()));
                    }
                }
            } catch (RuntimeException e) {
                if ("Unable to load the file".equals(e.getMessage())) {
                    System.err.println("WARNING: RFC4408 tests disabled.");
                    System.err.println("The RFC4408 test-suite is not bundled with jspf due to licensing issues.");
                    System.err.println("You can download the yaml testsuite at the following url:");
                    System.err.println("  http://www.openspf.org/source/project/test-suite/");
                    System.err.println("and place an rfc4408-tests.yml file in the /src/test/resources/org/apache/james/jspf folder.");
                }
            }
        }

    }
    
    protected void setLogger(Logger logger) {
        this.log = logger;
    }
    
    /**
     * This method has been created for spf spec people to let them better read the
     * output of our tests against their yaml file
     * 
     * @param args
     * @throws Throwable 
     */
    public static void main(String[] args) throws Throwable {
        Logger l = new Log4JLogger(org.apache.log4j.Logger.getLogger("ROOT"));

        List<SPFYamlTestDescriptor> tests = SPFYamlTestDescriptor.loadTests(YAMLFILE2);
        Iterator<SPFYamlTestDescriptor> i = tests.iterator();
        while (i.hasNext()) {
            SPFYamlTestDescriptor o = (SPFYamlTestDescriptor) i.next();
            Iterator<String> ttt = o.getTests().keySet().iterator();
            while (ttt.hasNext()) {
                RFC4408YamlTest t = new RFC4408YamlTest(o,(String) ttt.next());
                t.setLogger(l);
                TestRunner.run(t);
            }
        }
    }

}
