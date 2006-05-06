/***********************************************************************
 * Copyright (c) 2006-2006 The Apache Software Foundation.             *
 * All rights reserved.                                                *
 * ------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License"); you *
 * may not use this file except in compliance with the License. You    *
 * may obtain a copy of the License at:                                *
 *                                                                     *
 *     http://www.apache.org/licenses/LICENSE-2.0                      *
 *                                                                     *
 * Unless required by applicable law or agreed to in writing, software *
 * distributed under the License is distributed on an "AS IS" BASIS,   *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or     *
 * implied.  See the License for the specific language governing       *
 * permissions and limitations under the License.                      *
 ***********************************************************************/
package org.apache.james.jspf.macro;

import org.apache.james.jspf.exceptions.PermErrorException;

import junit.framework.TestCase;

/**
 * RFC4408 8.2. Expansion Examples
 */
public class MacroExpandTest extends TestCase {

    private final class rfcIP6MacroData extends rfcIP4MacroData {
        public String getInAddress() {
            return "ipv6";
        }

        public String getIpAddress() {
            return "2001:DB8::CB01";
        }

        public String getReadableIP() {
            return "2001:DB8::CB01";
        }
    }

    private class rfcIP4MacroData implements MacroData {
        public String getCurrentSenderPart() {
            return "strong-bad";
        }

        public String getMailFrom() {
            return "strong-bad@email.example.com";
        }

        public String getHostName() {
            return "email.example.com";
        }

        public String getCurrentDomain() {
            return "email.example.com";
        }

        public String getInAddress() {
            return "in-addr";
        }

        public String getClientDomain() {
            return "clientdomain";
        }

        public String getSenderDomain() {
            return "email.example.com";
        }

        public String getIpAddress() {
            return "192.0.2.3";
        }

        public long getTimeStamp() {
            return System.currentTimeMillis();
        }

        public String getReadableIP() {
            return "192.0.2.3";
        }

        public String getReceivingDomain() {
            return "receivingdomain";
        }
    }

    MacroExpand defIp4me = null;

    MacroExpand defIp6me = null;

    protected void setUp() throws Exception {
        super.setUp();
        defIp4me = new MacroExpand(new rfcIP4MacroData());
        defIp6me = new MacroExpand(new rfcIP6MacroData());
    }

    public void testPercS() throws PermErrorException {
        assertEquals("strong-bad@email.example.com", defIp4me
                .expandDomain("%{s}"));
    }

    public void testPercO() throws PermErrorException {
        assertEquals("email.example.com", defIp4me.expandDomain("%{o}"));
    }

    public void testPercD() throws PermErrorException {
        assertEquals("email.example.com", defIp4me.expandDomain("%{d}"));
        assertEquals("email.example.com", defIp4me.expandDomain("%{d4}"));
        assertEquals("email.example.com", defIp4me.expandDomain("%{d3}"));
        assertEquals("example.com", defIp4me.expandDomain("%{d2}"));
        assertEquals("com", defIp4me.expandDomain("%{d1}"));
        assertEquals("com.example.email", defIp4me.expandDomain("%{dr}"));
        assertEquals("example.email", defIp4me.expandDomain("%{d2r}"));
    }

    public void testPercL() throws PermErrorException {
        assertEquals("strong-bad", defIp4me.expandDomain("%{l}"));
        assertEquals("strong.bad", defIp4me.expandDomain("%{l-}"));
        assertEquals("strong-bad", defIp4me.expandDomain("%{lr}"));
        assertEquals("bad.strong", defIp4me.expandDomain("%{lr-}"));
        assertEquals("strong", defIp4me.expandDomain("%{l1r-}"));
    }

    public void testExample1() throws PermErrorException {
        assertEquals("3.2.0.192.in-addr._spf.example.com", defIp4me
                .expandDomain("%{ir}.%{v}._spf.%{d2}"));
    }

    public void testExample2() throws PermErrorException {
        assertEquals("bad.strong.lp._spf.example.com", defIp4me
                .expandDomain("%{lr-}.lp._spf.%{d2}"));
    }

    public void testExample3() throws PermErrorException {
        assertEquals("bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
                defIp4me.expandDomain("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}"));
    }

    public void testExample4() throws PermErrorException {
        assertEquals("3.2.0.192.in-addr.strong.lp._spf.example.com", defIp4me
                .expandDomain("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}"));
    }

    public void testExample5() throws PermErrorException {
        assertEquals("example.com.trusted-domains.example.net", defIp4me
                .expandDomain("%{d2}.trusted-domains.example.net"));
    }

    public void testExample6_ipv6() throws PermErrorException {
        // TODO fix this
        // assertEquals(
        // "1.0.B.C.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.ip6._spf.example.com",
        // defIp6me.expandDomain("%{ir}.%{v}._spf.%{d2}"));
    }

}
