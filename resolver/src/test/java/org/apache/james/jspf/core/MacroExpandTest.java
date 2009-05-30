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

package org.apache.james.jspf.core;

import org.apache.james.jspf.ConsoleLogger;
import org.apache.james.jspf.core.MacroData;
import org.apache.james.jspf.core.MacroExpand;
import org.apache.james.jspf.core.exceptions.PermErrorException;

import junit.framework.TestCase;

/**
 * RFC4408 8.2. Expansion Examples
 */
public class MacroExpandTest extends TestCase {

    private final class rfcIP6MacroData extends rfcIP4MacroData {
        public String getInAddress() {
            return "ip6";
        }

        public String getMacroIpAddress() {
            return "2.0.0.1.0.D.B.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.C.B.0.1";
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
        
        public String getMacroIpAddress() {
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
        defIp4me = new MacroExpand(new ConsoleLogger(), null);
        defIp6me = new MacroExpand(new ConsoleLogger(), null);
    }

    public void testPercS() throws PermErrorException {
        assertEquals("strong-bad@email.example.com", defIp4me
                .expand("%{s}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testPercK() throws PermErrorException {
        try {
            defIp4me.expand("%{k}", new rfcIP4MacroData(), MacroExpand.DOMAIN);
            fail("%{k} is not a valid expansion");
        } catch (PermErrorException e) {
        }
    }

    public void testPercentAloneIsError() throws PermErrorException {
        try {
            defIp4me.expand("%{s}%", new rfcIP4MacroData(), MacroExpand.DOMAIN);
            fail("invalid percent at end of line");
        } catch (PermErrorException e) {
        }
    }

    public void testDoublePercent() throws PermErrorException {
        assertEquals("%", defIp4me.expand("%%", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testPercO() throws PermErrorException {
        assertEquals("email.example.com", defIp4me.expand("%{o}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testPercD() throws PermErrorException {
        assertEquals("email.example.com", defIp4me.expand("%{d}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("email.example.com", defIp4me.expand("%{d4}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("email.example.com", defIp4me.expand("%{d3}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("example.com", defIp4me.expand("%{d2}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("com", defIp4me.expand("%{d1}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("com.example.email", defIp4me.expand("%{dr}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("example.email", defIp4me.expand("%{d2r}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testPercL() throws PermErrorException {
        assertEquals("strong-bad", defIp4me.expand("%{l}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("strong.bad", defIp4me.expand("%{l-}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("strong-bad", defIp4me.expand("%{lr}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("bad.strong", defIp4me.expand("%{lr-}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("strong", defIp4me.expand("%{l1r-}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testExample1() throws PermErrorException {
        assertEquals("3.2.0.192.in-addr._spf.example.com", defIp4me
                .expand("%{ir}.%{v}._spf.%{d2}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testExample2() throws PermErrorException {
        assertEquals("bad.strong.lp._spf.example.com", defIp4me
                .expand("%{lr-}.lp._spf.%{d2}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testExample3() throws PermErrorException {
        assertEquals("bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
                defIp4me.expand("%{lr-}.lp.%{ir}.%{v}._spf.%{d2}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testExample4() throws PermErrorException {
        assertEquals("3.2.0.192.in-addr.strong.lp._spf.example.com", defIp4me
                .expand("%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testExample5() throws PermErrorException {
        assertEquals("example.com.trusted-domains.example.net", defIp4me
                .expand("%{d2}.trusted-domains.example.net", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testExample6_ipv6() throws PermErrorException {
        assertEquals(
                "1.0.B.C.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.ip6._spf.example.com",
                defIp6me.expand("%{ir}.%{v}._spf.%{d2}", new rfcIP6MacroData(), MacroExpand.EXPLANATION));
    }
    
    public void testLocalPartWithSpecialChars() throws PermErrorException {
    	defIp4me.expand("+exists:CL.%{i}.FR.%{s}.spf.test.com", new rfcIP4MacroData() {
    		public String getMailFrom() {
    			return "test{$LNAME}@email.example.com";
    		}
    		   public String getCurrentSenderPart() {
    	            return "test{$LNAME}";
    	        }
    	}, MacroExpand.DOMAIN);
    }

}
