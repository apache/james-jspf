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

package org.apache.james.jspf.dnsserver;

import org.apache.james.jspf.ConsoleLogger;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.xbill.DNS.Cache;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import junit.framework.TestCase;

public class DNSTestingServerTest extends TestCase {

    private DNSTestingServer server;
    private Cache origCache;
    private Resolver origResolver;
    private Name[] origSearchPaths;
    private DNSService dnsService;

    protected void setUp() throws Exception {
        server = new DNSTestingServer("0.0.0.0", "34876");
        origCache = Lookup.getDefaultCache(DClass.IN);
        origResolver = Lookup.getDefaultResolver();
        origSearchPaths = Lookup.getDefaultSearchPath();
        
        Lookup.setDefaultSearchPath(new Name[] {});
        Lookup.setDefaultCache(null, DClass.IN);
        SimpleResolver simpleResolver = new SimpleResolver("127.0.0.1");
        simpleResolver.setPort(34876);
        Lookup.setDefaultResolver(simpleResolver);
        
        dnsService = new DNSServiceXBillImpl(new ConsoleLogger());
    }
    
    public void testNothing() {
        
    }
//    public void testSimple() throws TimeoutException {
//        List res = dnsService.getRecords(new DNSRequest("test.foo.bar.", DNSRequest.MX));
//        System.out.println(res);
//        
//    }

    protected void tearDown() throws Exception {
        Lookup.setDefaultCache(origCache, DClass.IN);
        Lookup.setDefaultResolver(origResolver);
        Lookup.setDefaultSearchPath(origSearchPaths);
    }

    
}
