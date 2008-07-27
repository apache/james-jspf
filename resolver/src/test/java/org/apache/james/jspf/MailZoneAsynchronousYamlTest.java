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

import org.apache.james.jspf.core.DNSService;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestSuite;

public class MailZoneAsynchronousYamlTest extends MailZoneYamlTest {

    private static final String YAMLFILE2 = "mailzone-tests.yml";

    /**
     * @param name
     * @throws IOException
     */
    public MailZoneAsynchronousYamlTest(String name) throws IOException {
        super(name);
    }

    protected MailZoneAsynchronousYamlTest(SPFYamlTestDescriptor def, String test) {
        super(def, test);
    }

    protected MailZoneAsynchronousYamlTest(SPFYamlTestDescriptor def) {
        super(def);
    }

    protected String getFilename() {
        return YAMLFILE2;
    }

    public static Test suite() throws IOException {
        return new MailZoneAsynchronousSuite();
    }

    protected List internalLoadTests(String filename) throws IOException {
        return loadTests(filename);
    }

    protected DNSService getDNSService() {
        DNSService dns = super.getDNSService();
        // Remove record limits for this test
        dns.setRecordLimit(0);
        return dns;
    }
    
    
    protected int getDnsServiceMockStyle() {
        return FAKE_SERVER;
    }

    protected int getSpfExecutorType() {
        return STAGED_EXECUTOR_DNSJNIO;
    }

    static class MailZoneAsynchronousSuite extends TestSuite {

        public MailZoneAsynchronousSuite() throws IOException {
            super();
            List tests = loadTests(YAMLFILE2);
            Iterator i = tests.iterator();
            while (i.hasNext()) {
                SPFYamlTestDescriptor o = (SPFYamlTestDescriptor) i.next();
                addTest(new MailZoneAsynchronousYamlTest(o));
            }
        }

    }

}
