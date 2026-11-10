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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class SPF1UtilsTest {

    private static final String FORMER_REGEX = "(([a-zA-Z0-9\\-])+\\.)+([a-zA-Z]+)$";

    @Test
    public void checkFQDNShouldAcceptTheLanguageOfTheFormerRegex() {
        String[] hosts = {"", ".", "com", "example.com", "a.b.example.com", "-.x", "a-1.b2.COM", "example.com.",
            ".example.com", "a..com", "example.c0m", "example.com\n", "exa_mple.com", "1.2.3.4", "é.com", "a.b-"};
        for (String host : hosts) {
            assertEquals(host, host.matches(FORMER_REGEX), SPF1Utils.checkFQDN(host));
        }
    }

    @Test
    public void checkFQDNShouldNotOverflowTheStackOnManyLabels() {
        assertTrue(SPF1Utils.checkFQDN("a.".repeat(100_000) + "com"));
    }
}
