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

package org.apache.james.jspf.parser;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Collections;
import java.util.regex.Pattern;

import org.junit.Test;

public class RFC4408SPF1ParserSplitTermsTest {

    @Test
    public void shouldDropTheVersionAndSplitOnSpaces() {
        assertEquals(Arrays.asList("mx", "-all"), RFC4408SPF1Parser.splitTerms("v=spf1 mx -all"));
    }

    @Test
    public void shouldSkipTheEmptyTermsOfSeveralSpaces() {
        assertEquals(Arrays.asList("a", "mx", "-all"), RFC4408SPF1Parser.splitTerms("v=spf1   a  mx -all   "));
    }

    @Test
    public void shouldGiveNoTermForASpaceOnly() {
        assertEquals(Collections.emptyList(), RFC4408SPF1Parser.splitTerms("v=spf1 "));
    }

    @Test
    public void shouldDropTheVersionCaseSensitivelyAsBefore() {
        assertEquals(Arrays.asList("V=SPF1", "a"), RFC4408SPF1Parser.splitTerms("V=SPF1 a"));
    }

    @Test
    public void shouldGiveTheTermsOfTheFormerRegexSplit() {
        Pattern separator = Pattern.compile("[ ]+");
        String[] records = {"v=spf1 a", "v=spf1  a  b", "v=spf1 a v=spf1 b", "V=SPF1 a v=spf1 b",
            "v=spf1 redirect=v=spf1.example.com", "v=spf1     ", "v=spf1 include:x  -all  "};
        for (String record : records) {
            java.util.List<String> expected = new java.util.ArrayList<>();
            for (String term : separator.split(record.replaceFirst("v=spf1", ""))) {
                if (term.length() > 0) {
                    expected.add(term);
                }
            }
            assertEquals(record, expected, RFC4408SPF1Parser.splitTerms(record));
        }
    }
}
