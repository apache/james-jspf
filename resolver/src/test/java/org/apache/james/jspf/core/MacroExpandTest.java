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
        defIp4me = new MacroExpand(null);
        defIp6me = new MacroExpand(null);
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

    public void testDigitTransformerAboveAnIntKeepsAllTheParts() throws PermErrorException {
        assertEquals("email.example.com", defIp4me.expand("%{d99999999999}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("com.example.email", defIp4me.expand("%{d99999999999r}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testLongZeroDigitTransformerIsError() {
        try {
            defIp4me.expand("%{d00000000000}", new rfcIP4MacroData(), MacroExpand.DOMAIN);
            fail("zero digit transformer");
        } catch (PermErrorException e) {
        }
    }

    public void testPercL() throws PermErrorException {
        assertEquals("strong-bad", defIp4me.expand("%{l}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("strong.bad", defIp4me.expand("%{l-}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("strong-bad", defIp4me.expand("%{lr}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("bad.strong", defIp4me.expand("%{lr-}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
        assertEquals("strong", defIp4me.expand("%{l1r-}", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testLongDomainSpecIsTruncatedWithoutOverflowingTheStack() throws PermErrorException {
        String domain = defIp4me.expand("%{d}.".repeat(5000) + "com", new rfcIP4MacroData(), MacroExpand.DOMAIN);

        assertTrue(domain.length() <= 253);
        assertTrue(domain.endsWith(".email.example.com.com"));
    }

    public void testLongDomainIsCutAfterTheFirstDotThatLeavesAtMost253Characters() throws PermErrorException {
        String domain = defIp4me.expand("a.".repeat(200) + "com", new rfcIP4MacroData(), MacroExpand.DOMAIN);

        // RFC 7208 7.3
        assertEquals("a.".repeat(125) + "com", domain);
    }

    public void testLongLastLabelOfALongDomainIsKeptWhole() throws PermErrorException {
        String domain = defIp4me.expand("%{d}." + "a".repeat(300), new rfcIP4MacroData(), MacroExpand.DOMAIN);

        assertEquals("a".repeat(300), domain);
    }

    public void testLongLiteralDomainSpecIsTruncatedWithoutOverflowingTheStack() throws PermErrorException {
        String domain = defIp4me.expand("a.".repeat(5000) + "com", new rfcIP4MacroData(), MacroExpand.DOMAIN);

        assertTrue(domain.length() <= 253);
        assertTrue(domain.endsWith(".a.com"));
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

        assertEquals(
                "+exists:CL.192.0.2.3.FR.test{$LNAME}@email.example.com.spf.test.com",
                defIp4me.expand("+exists:CL.%{i}.FR.%{s}.spf.test.com",
                        new rfcIP4MacroData() {
                            public String getMailFrom() {
                                return "test{$LNAME}@email.example.com";
                            }

                            public String getCurrentSenderPart() {
                                return "test{$LNAME}";
                            }
                        }, MacroExpand.DOMAIN));

        // not sure if \ is allowed in email, but anyway make sure we correctly handle also backslash.
        assertEquals(
                "+exists:CL.192.0.2.3.FR.tes\\t{$LNAME}@email.example.com.spf.test.com",
                defIp4me.expand("+exists:CL.%{i}.FR.%{s}.spf.test.com",
                        new rfcIP4MacroData() {
                            public String getMailFrom() {
                                return "tes\\t{$LNAME}@email.example.com";
                            }

                            public String getCurrentSenderPart() {
                                return "tes\\t{$LNAME}";
                            }
                        }, MacroExpand.DOMAIN));
    }

    public void testSplitKeepsTheEmptyParts() {
        assertEquals(java.util.Arrays.asList("", "a", "", "b", ""), MacroExpand.split(".a..b.", "."));
        assertEquals(java.util.Arrays.asList(""), MacroExpand.split("", "."));
    }

    public void testSplitOnEachDelimiter() {
        assertEquals(java.util.Arrays.asList("a", "b", "c", "d"), MacroExpand.split("a-b+c.d", ".-+"));
    }

    public void testEmptyPartsAreKeptInTheExpansion() throws PermErrorException {
        assertEquals("bad..strong", defIp4me.expand("%{lr-}", new rfcIP4MacroData() {
            public String getCurrentSenderPart() {
                return "strong--bad";
            }
        }, MacroExpand.DOMAIN));
    }
    public void testAnExplanationUnderTheLimitIsExpanded() throws PermErrorException {
        String explanation = defIp4me.expand("%{d} ".repeat(50), new rfcIP4MacroData(), MacroExpand.EXPLANATION);

        assertEquals("email.example.com ".repeat(50).trim(), explanation);
    }

    public void testAnExplanationExpandedPastTheLimitIsAPermError() {
        // a few KB of macros, each growing into the whole sender domain
        String[] inputs = {"%{d}".repeat(2000), "%{d} ".repeat(2000), "a".repeat(MacroExpand.MAX_EXPLANATION_LENGTH + 1)};
        for (String input : inputs) {
            try {
                defIp4me.expand(input, new rfcIP4MacroData(), MacroExpand.EXPLANATION);
                fail("an explanation longer than " + MacroExpand.MAX_EXPLANATION_LENGTH + " characters should be a permerror");
            } catch (PermErrorException e) {
            }
        }
    }

    public void testPlainTargetIsReturnedAsIs() throws PermErrorException {
        assertEquals("_spf.mail.example.net", defIp4me.expand("_spf.mail.example.net", new rfcIP4MacroData(), MacroExpand.DOMAIN));
    }

    public void testInvalidMacroExpandsAreErrors() {
        String[] invalid = {"a%", "%{", "%{d", "%{dR}", "%{x}", "%{}", "%a", "a\tb%{d}", "\u00e9%{d}", "%{d1.2}"};
        for (String input : invalid) {
            try {
                defIp4me.expand(input, new rfcIP4MacroData(), MacroExpand.EXPLANATION);
                fail(input + " should be a permerror");
            } catch (PermErrorException e) {
                // expected
            }
        }
    }

    public void testMacroValueWithReplacementCharactersIsCopied() throws PermErrorException {
        assertEquals("a$1\\b.x", defIp4me.expand("%{l}.x", new rfcIP4MacroData() {
            public String getCurrentSenderPart() {
                return "a$1\\b";
            }
        }, MacroExpand.EXPLANATION));
    }

    /**
     * The former tokenizer: a regex find per macro-expand or macro-literal, each cell expanded alone.
     */
    private String referenceExpansion(String input, MacroData data) throws PermErrorException {
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(SPFTermsRegexps.MACRO_STRING_REGEX_TOKEN).matcher(input);
        StringBuilder out = new StringBuilder();
        int pos = 0;
        while (matcher.find()) {
            if (pos != matcher.start()) {
                throw new PermErrorException("Middle part does not match");
            }
            String token = matcher.group();
            if (token.startsWith("%{")) {
                out.append(defIp4me.expand(token, data, MacroExpand.EXPLANATION));
            } else if ("%_".equals(token)) {
                out.append(' ');
            } else if ("%-".equals(token)) {
                out.append("%20");
            } else if ("%%".equals(token)) {
                out.append('%');
            } else {
                out.append(token);
            }
            pos = matcher.end();
        }
        if (pos != input.length()) {
            throw new PermErrorException("End part does not match");
        }
        return out.toString();
    }

    public void testExpansionIsTheOneOfTheFormerTokenizer() {
        String[] pieces = {"%", "{", "}", "%{", "%%", "%_", "%-", "d", "l", "i", "r", "c", "k", "R", "1", "2", "0",
            ".", "-", "+", "=", "/", ",", "_", "$", "\\", "a", "\u00e9", "\t", "~", "!"};
        java.util.Random random = new java.util.Random(42);
        for (int n = 0; n < 20000; n++) {
            StringBuilder input = new StringBuilder();
            int length = random.nextInt(8);
            for (int k = 0; k < length; k++) {
                input.append(pieces[random.nextInt(pieces.length)]);
            }
            String expected;
            try {
                expected = referenceExpansion(input.toString(), new rfcIP4MacroData());
            } catch (PermErrorException e) {
                expected = "permerror";
            }
            String actual;
            try {
                actual = defIp4me.expand(input.toString(), new rfcIP4MacroData(), MacroExpand.EXPLANATION);
            } catch (PermErrorException e) {
                actual = "permerror";
            }
            assertEquals(input.toString(), expected, actual);
        }
    }
}
