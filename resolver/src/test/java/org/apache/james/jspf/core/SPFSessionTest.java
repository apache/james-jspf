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

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class SPFSessionTest {
    @Test
    public void testGetMacroIpAddress() {
        SPFSession d = new SPFSession("mailfrom@fromdomain.com","helodomain.com","2001:DB8::CB01");
        assertEquals("2.0.0.1.0.D.B.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.C.B.0.1",d.getMacroIpAddress());
    }

    @Test
    public void shouldReturnInvalidIP6() {
        String addr = "2001:db8::644:f:f:f:x";
        SPFSession spfSession = new SPFSession("", "", addr);
        assertEquals("invalid", spfSession.getInAddress());
    }

    @Test
    public void shouldReturnInvalidIP4() {
        String addr = "192.168.0.256";
        SPFSession spfSession = new SPFSession("", "", addr);
        assertEquals("invalid", spfSession.getInAddress());
    }

    @Test
    public void shouldReturnValidIP6() {
        String addr = "2001:db8::644:f:f:f:1";
        SPFSession spfSession = new SPFSession("", "", addr);
        assertEquals("ip6", spfSession.getInAddress());
    }

    @Test
    public void shouldReturnIPv4Mapped() {
        SPFSession spfSession = new SPFSession("", "", "::ffff:192.168.1.1");
        assertEquals("ip6", spfSession.getInAddress());
    }

    @Test
    public void shouldReturnIPv4() {
        SPFSession spfSession = new SPFSession("", "", "192.168.1.1");
        assertEquals("in-addr", spfSession.getInAddress());
    }
}
