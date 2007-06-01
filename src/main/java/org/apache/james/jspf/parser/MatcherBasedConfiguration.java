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

import org.apache.james.jspf.core.Configuration;

import java.util.regex.Matcher;

/**
 * 
 * Provides a MatchResult view of a subset of another MatchResult
 */
public class MatcherBasedConfiguration implements Configuration {

    private Matcher wrapped;

    private int start;

    private int count;

    /**
     * @param w
     *            Original MatchResult
     * @param zero
     *            The original index returned when group(0) is requested
     * @param start
     *            the position where the subresult start
     * @param count
     *            number of groups part of the subresult
     */
    public MatcherBasedConfiguration(Matcher w, int start, int count) {
        this.wrapped = w;
        this.count = count;
        this.start = start;
    }

    /**
     * @see org.apache.james.jspf.core.Configuration#group(int)
     */
    public String group(int arg0) {
        return wrapped.group(arg0 + start);
    }

    /**
     * @see org.apache.james.jspf.core.Configuration#groupCount()
     */
    public int groupCount() {
        return count;
    }

}