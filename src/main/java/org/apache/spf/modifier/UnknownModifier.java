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

package org.apache.spf.modifier;

import org.apache.spf.Configurable;
import org.apache.spf.PermErrorException;
import org.apache.spf.SPF1Data;
import org.apache.spf.SPF1Parser;

import java.util.regex.MatchResult;

public class UnknownModifier implements Modifier, Configurable {

    /**
     * ABNF: name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
     * ABNF: unknown-modifier = name "=" macro-string
     */
    public static final String REGEX = "(" + SPF1Parser.ALPHA_PATTERN + "{1}"
        + "[A-Za-z0-9\\-\\_\\.]*" + ")" + "\\=(" + SPF1Parser.MACRO_STRING_REGEX + ")";


    /**
     * @see org.apache.spf.modifier.Modifier#run(org.apache.spf.SPF1Data)
     */
    public String run(SPF1Data spfData) throws PermErrorException {
        return null;
    }

    /**
     * @see org.apache.spf.modifier.Modifier#enforceSingleInstance()
     */
    public boolean enforceSingleInstance() {
        return false;
    }

    public void config(MatchResult params) throws PermErrorException {
        // Nothing to do
    }

}
