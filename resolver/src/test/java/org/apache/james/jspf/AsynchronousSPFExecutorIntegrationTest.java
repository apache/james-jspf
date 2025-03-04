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
import org.apache.james.jspf.executor.AsynchronousSPFExecutor;
import org.apache.james.jspf.impl.DefaultSPF;
import org.apache.james.jspf.impl.SPF;
import org.junit.BeforeClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.SimpleResolver;

import java.net.UnknownHostException;

/**
 * Class to run the tests using {@link AsynchronousSPFExecutor}
 */
public class AsynchronousSPFExecutorIntegrationTest extends SPFExecutorBaseTest {
    @BeforeClass
    public static void setup() {
        // set default resolver before the tests to avoid errors caused by previous tests
        try {
            Lookup.setDefaultResolver(new SimpleResolver());
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    protected SPF createSPF() {
        return DefaultSPF.createAsync();
    }

    @Override
    protected SPF createCustomSPF(DNSService dnsService) {
        return new SPF(dnsService, new AsynchronousSPFExecutor(dnsService));
    }
}
