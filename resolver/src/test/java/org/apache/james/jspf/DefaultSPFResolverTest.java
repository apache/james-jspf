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

import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.impl.DefaultSPF;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.SimpleResolver;

import java.net.UnknownHostException;

import static org.junit.Assert.assertEquals;

public class DefaultSPFResolverTest {
    @BeforeClass
    public static void setup() {
        // set default resolver before the tests to avoid errors caused by previous tests
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
    public void shouldHandleDomainNotFound() {
        SPFResult spfResult = new DefaultSPF().checkSPF("207.54.72.202",
                "do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de",
                "reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de");
        assertEquals("none", spfResult.getResult());
        assertEquals("Received-SPF: none (spfCheck: 207.54.72.202 is neither permitted nor denied by domain of reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de) client-ip=207.54.72.202; envelope-from=do_not_reply@reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de; helo=reyifglerifwukfvbdjhrkbvebvekvfulervkerkeruerbeb.de;",
                spfResult.getHeader());
    }

    @Test
    public void shouldHandleSPFNotFound() {
        SPFResult spfResult = new DefaultSPF().checkSPF("207.54.72.202",
                "do_not_reply@com.br", "com.br");
        assertEquals("none", spfResult.getResult());
        assertEquals("Received-SPF: none (spfCheck: 207.54.72.202 is neither permitted nor denied by domain of com.br) client-ip=207.54.72.202; envelope-from=do_not_reply@com.br; helo=com.br;",
                spfResult.getHeader());
    }
}
