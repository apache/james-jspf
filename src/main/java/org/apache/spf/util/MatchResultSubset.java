/***********************************************************************
 * Copyright (c) 1999-2006 The Apache Software Foundation.             *
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

package org.apache.spf.util;

import java.util.regex.MatchResult;

/**
 * @author Stefano Bagnara
 * 
 * Provides a MatchResult view of a subset of another MatchResult
 */
public class MatchResultSubset implements MatchResult {
    
    private MatchResult wrapped;
    private int start;
    private int count;
    
    /**
     * @param w Original MatchResult
     * @param zero The original index returned when group(0) is requested
     * @param start the position where the subresult start
     * @param count number of groups part of the subresult
     */
    public MatchResultSubset(MatchResult w, int start, int count) {
        this.wrapped = w;
        this.count = count;
        this.start = start;
    }
    
    /**
     * @see java.util.regex.MatchResult#end()
     */
    public int end() {
        throw new UnsupportedOperationException();
    }
    
    /**
     * @see java.util.regex.MatchResult#end(int)
     */
    public int end(int arg0) {
        throw new UnsupportedOperationException();
    }
    
    /**
     * @see java.util.regex.MatchResult#group()
     */
    public String group() {
        throw new UnsupportedOperationException();
    }
    
    /**
     * @see java.util.regex.MatchResult#group(int)
     */
    public String group(int arg0) {
        return wrapped.group(arg0+start);
    }
    
    /**
     * @see java.util.regex.MatchResult#groupCount()
     */
    public int groupCount() {
        return count;
    }
    
    /**
     * @see java.util.regex.MatchResult#start()
     */
    public int start() {
        throw new UnsupportedOperationException();
    }
    
    /**
     * @see java.util.regex.MatchResult#start(int)
     */
    public int start(int arg0) {
        throw new UnsupportedOperationException();
    }

}