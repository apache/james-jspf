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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.UnknownHostException;

import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.impl.DefaultSPF;
import org.apache.james.jspf.impl.SPF;
import org.junit.Test;

import org.xbill.DNS.ExtendedResolver;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;

public class AsynchronousSPFExecutorIntegrationTest {

    private SPF createAsyncSPF() {
        return createAsyncSPF((String[]) null);
    }

    private SPF createAsyncSPF(String dnsResolvers) {
        return createAsyncSPF(dnsResolvers.split("\\s*;\\s*"));
    }

    /**
     * Mimics the logic in the new SPF() 
     */
    private SPF createAsyncSPF(String[] dnsResolvers) {
        DNSServiceXBillImpl dnsProbe;

        // when we have no specific DNS resolvers to use, we use the default DNS of the JVM 
        if( dnsResolvers == null ){
            dnsProbe = new DNSServiceXBillImpl();
        } else {
            try {
                dnsProbe = new DNSServiceXBillImpl(new ExtendedResolver(dnsResolvers));
            } catch (UnknownHostException e) {
                fail("Resolver could not be created");
                dnsProbe = null;
            }
        }

        return new SPF(dnsProbe);
    }

    @Test
    public void testWithDefaultSPF() {
        SPF spf = new DefaultSPF();
        SPFResult result = spf.checkSPF("109.197.176.25", "nico@linagora.com", "linagora.com");
        System.out.println(result.getResult());
        System.out.println(result.getExplanation());
        System.out.println(result.getHeader());
        assertEquals("pass", result.getResult());
        assertEquals("Received-SPF: pass (spfCheck: domain of linagora.com designates 109.197.176.25 as permitted sender) client-ip=109.197.176.25; envelope-from=nico@linagora.com; helo=linagora.com;",
            result.getHeader());
    }

    @Test
    public void testSPFWithAsynchronousSPFExecutor() {
        SPF spf = createAsyncSPF(); 
        SPFResult result = spf.checkSPF("109.197.176.25", "nico@linagora.com", "linagora.com");
        System.out.println(result.getResult());
        System.out.println(result.getExplanation());
        System.out.println(result.getHeader());
        assertEquals("pass", result.getResult());
        assertEquals("Received-SPF: pass (spfCheck: domain of linagora.com designates 109.197.176.25 as permitted sender) client-ip=109.197.176.25; envelope-from=nico@linagora.com; helo=linagora.com;",
            result.getHeader());
    }

    @Test
    public void shouldParseWireParseExceptionWhenRecordTruncated() {
        SPF spf = createAsyncSPF("1.1.1.1; 1.0.0.1"); // use CloudFlare's DNS server to resolve DNS entries
        SPFResult result = spf.checkSPF("170.146.224.15", "HelpDesk@arcofmc.org", "arcofmc.org");
        System.out.println(result.getResult());
        System.out.println(result.getExplanation());
        System.out.println(result.getHeader());
        assertEquals("permerror", result.getResult());
        assertEquals("Received-SPF: permerror (spfCheck: Error in processing SPF Record) client-ip=170.146.224.15; envelope-from=HelpDesk@arcofmc.org; helo=arcofmc.org;",
            result.getHeader());
    }
}