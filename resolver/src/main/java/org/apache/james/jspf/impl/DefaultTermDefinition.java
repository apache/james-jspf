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

package org.apache.james.jspf.impl;


import org.apache.james.jspf.parser.TermDefinition;

import java.util.regex.Pattern;

/**
 * Default implementation for the TermDefinition.
 * This implementation try to retrieve the definition looking up a
 * static REGEX field in the term class.
 */
public class DefaultTermDefinition implements TermDefinition {

    private Pattern pattern;

    private Class<?> termDef;

    private int matchSize = 0;

    public DefaultTermDefinition(Class<?> tClass) throws IllegalArgumentException,
            SecurityException, IllegalAccessException, NoSuchFieldException {
        String pString = (String) tClass.getField("REGEX").get(null);
        pattern = Pattern.compile(pString);
        termDef = tClass;
        calcGroups(pString);
    }

    /**
     * This method should be done differently. We currently don't hanlde the
     * escaping at all.
     * 
     * @param pString
     */
    private void calcGroups(String pString) {
        int i = 0;
        int c = 0;
        while (true) {
            int p1 = pString.indexOf("(", i);
            int p2 = pString.indexOf("(?:", i);
            if (p1 < 0)
                break;
            if (p1 != p2)
                c++;
            i = p1 + 1;
        }
        matchSize = c;
    }

    /**
     * @see org.apache.james.jspf.parser.TermDefinition#getPattern()
     */
    public Pattern getPattern() {
        return pattern;
    }

    /**
     * @see org.apache.james.jspf.parser.TermDefinition#getTermDef()
     */
    public Class<?> getTermDef() {
        return termDef;
    }

    /**
     * @see org.apache.james.jspf.parser.TermDefinition#getMatchSize()
     */
    public int getMatchSize() {
        return matchSize;
    }
}