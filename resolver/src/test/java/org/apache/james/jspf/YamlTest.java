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

import junit.framework.Test;
import junit.framework.TestSuite;

public class YamlTest extends AbstractYamlTest {

    private static final String YAMLFILE2 = "tests.yml";

    /**
     * @param name
     * @throws IOException
     */
    public YamlTest(String name) throws IOException {
        super(name);
    }

    protected YamlTest(SPFYamlTestDescriptor def, String test) {
        super(def, test);
    }

    protected String getFilename() {
        return YAMLFILE2;
    }

    public static Test suite() throws IOException {
        return new BasicSuite();
    }

    protected List internalLoadTests(String filename) throws IOException {
        return loadTests(filename);
    }

    static class BasicSuite extends TestSuite {

        public BasicSuite() throws IOException {
            super();
            List tests = loadTests(YAMLFILE2);
            Iterator i = tests.iterator();
            while (i.hasNext()) {
                SPFYamlTestDescriptor o = (SPFYamlTestDescriptor) i.next();
                Iterator ttt = o.getTests().keySet().iterator();
                while (ttt.hasNext()) {
                    addTest(new YamlTest(o,(String) ttt.next()));
                }
            }
        }

    }

}
