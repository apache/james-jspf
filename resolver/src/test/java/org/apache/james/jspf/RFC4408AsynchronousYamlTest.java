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

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import org.apache.james.jspf.tester.SPFYamlTestDescriptor;

import junit.framework.Test;
import junit.framework.TestSuite;
import junit.textui.TestRunner;

public class RFC4408AsynchronousYamlTest extends RFC4408YamlTest {

    private static final String YAMLFILE2 = "rfc4408-tests.yml";
    /**
     * @param name
     * @throws IOException
     */
    public RFC4408AsynchronousYamlTest(String name) throws IOException {
        super(name);
    }

    protected RFC4408AsynchronousYamlTest(SPFYamlTestDescriptor def) {
        super(def);
    }

    protected RFC4408AsynchronousYamlTest(SPFYamlTestDescriptor def, String test) {
        super(def, test);
    }

    protected String getFilename() {
        return YAMLFILE2;
    }

    public static Test suite() throws IOException {
        return new RFC4408AsynchronousSuite();
    }

    protected int getDnsServiceMockStyle() {
        return FAKE_SERVER;
    }

    protected int getSpfExecutorType() {
        return STAGED_EXECUTOR_MULTITHREADED;
    }

    static class RFC4408AsynchronousSuite extends TestSuite {

        public RFC4408AsynchronousSuite() throws IOException {
            super();
            List<SPFYamlTestDescriptor> tests = SPFYamlTestDescriptor.loadTests(YAMLFILE2);
            Iterator<SPFYamlTestDescriptor> i = tests.iterator();
            while (i.hasNext()) {
                SPFYamlTestDescriptor o = i.next();
                addTest(new RFC4408AsynchronousYamlTest(o));
            }
        }

    }
    
    /**
     * This method has been created for spf spec people to let them better read the
     * output of our tests against their yaml file
     * 
     * @param args
     * @throws Throwable 
     */
    public static void main(String[] args) throws Throwable {
        List<SPFYamlTestDescriptor> tests = SPFYamlTestDescriptor.loadTests(YAMLFILE2);
        Iterator<SPFYamlTestDescriptor> i = tests.iterator();
        while (i.hasNext()) {
            SPFYamlTestDescriptor o = (SPFYamlTestDescriptor) i.next();
            Iterator<String> ttt = o.getTests().keySet().iterator();
            while (ttt.hasNext()) {
                RFC4408AsynchronousYamlTest t = new RFC4408AsynchronousYamlTest(o, ttt.next());
                TestRunner.run(t);
            }
        }
    }

}
