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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.james.jspf.terms.Directive;
import org.apache.james.jspf.terms.Modifier;

/**
 * The Class represent the SPF1 Record and provide methods to get all directives
 * and modifiers.
 * 
 */
public class SPF1Record {
    
    private String record;
    private List<Directive> directives = new ArrayList<Directive>();
    private List<Modifier> modifiers = new ArrayList<Modifier>();

    public SPF1Record() {
        this.record = null;
    }
    
    public SPF1Record(String record) {
        this.record = record;
    }

    /**
     * Return the directives as Collection
     * 
     * @return directives Collection of all qualifier+mechanism which should be
     *         used
     */
    public List<Directive> getDirectives() {
        return directives;
    }

    /**
     * Return the modifiers as Collection
     * 
     * @return modifiers Collection of all modifiers which should be used
     */
    public List<Modifier> getModifiers() {
        return modifiers;
    }

    /**
     * @return the record in its string source format
     */
    public String getRecord() {
        return record;
    }
    
    /**
     * Return a single iterator over Directives and Modifiers
     * 
     * @return a chained iterator of the terms
     */
    @SuppressWarnings("unchecked")
	public Iterator<SPFChecker> iterator() {
        return new Iterator() {
            boolean first = true;
            Iterator current = getDirectives().iterator();

            /**
             * @see java.util.Iterator#hasNext()
             */
            public boolean hasNext() {
                if (current.hasNext()) { 
                    return true;
                } else if (first) {
                    current = getModifiers().iterator();
                    first = false;
                    return current.hasNext();
                } else return false;
            }

            /**
             * @see java.util.Iterator#next()
             */
            public Object next() {
                return current.next();
            }

            /**
             * @see java.util.Iterator#remove()
             */
            public void remove() {
                throw new UnsupportedOperationException("Readonly iterator");
            }
            
        };
    }

}
