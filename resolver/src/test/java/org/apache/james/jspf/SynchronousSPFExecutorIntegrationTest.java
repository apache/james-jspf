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

import org.apache.james.jspf.executor.AsynchronousSPFExecutor;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.executor.SynchronousSPFExecutor;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.apache.james.jspf.impl.DefaultSPF;
import org.apache.james.jspf.impl.SPF;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import java.net.UnknownHostException;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.Assert.assertEquals;

public class SynchronousSPFExecutorIntegrationTest {
    @BeforeClass
    public static void setup() {
        System.out.println("Setting default resolver");
        try {
            Lookup.setDefaultResolver(new SimpleResolver());
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Before
    public void clearDnsCache() {
        Lookup.getDefaultCache(DClass.IN).clearCache();
    }

    @Test
    public void test() {
        SPF spf = DefaultSPF.createSync();
        SPFResult result = spf.checkSPF("109.197.176.25", "nico@linagora.com", "linagora.com");
        System.out.println(result.getResult());
        System.out.println(result.getExplanation());
        System.out.println(result.getHeader());
        assertEquals("pass", result.getResult());
        assertEquals("Received-SPF: pass (spfCheck: domain of linagora.com designates 109.197.176.25 as permitted sender) client-ip=109.197.176.25; envelope-from=nico@linagora.com; helo=linagora.com;",
            result.getHeader());
    }

    @Test
    public void shouldHandleDomainNotFound() {
        SPF spf = DefaultSPF.createSync();
        SPFResult result = spf.checkSPF("207.54.72.202","do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de","reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de");
        System.out.println(result.getResult());
        System.out.println(result.getExplanation());
        System.out.println(result.getHeader());
        assertEquals("none", result.getResult());
    }

    @Test
    public void shouldHandleSPFNotFound() {
        SPF spf = DefaultSPF.createSync();
        SPFResult result = spf.checkSPF("207.54.72.202","do_not_reply@com.br","com.br");
        System.out.println(result.getResult());
        System.out.println(result.getExplanation());
        System.out.println(result.getHeader());
        assertEquals("none", result.getResult());
    }

    @Test
    public void shouldReturnTempErrorOnPortUnreachable() throws UnknownHostException {
        Resolver simpleResolver = new SimpleResolver("127.0.0.1");
        simpleResolver.setPort(ThreadLocalRandom.current().nextInt(55000, 56000));

        DNSServiceXBillImpl dns = new DNSServiceXBillImpl(simpleResolver);

        SPF spf = new SPF(dns, new SynchronousSPFExecutor(dns));
        SPFResult result = spf.checkSPF("207.54.72.202",
                "do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de",
                "reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de");
        System.out.println(result.getResult());
        System.out.println(result.getExplanation());
        System.out.println(result.getHeader());
        assertEquals("temperror", result.getResult());
    }
}