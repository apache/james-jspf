/***********************************************************************
 * Copyright (c) 2006 The Apache Software Foundation.             *
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

package org.apache.james.jspf.terms;

import org.apache.james.jspf.core.Configurable;
import org.apache.james.jspf.core.Modifier;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.parser.SPF1Parser;
import org.apache.james.jspf.util.ConfigurationMatch;

/**
 * This Class represent an Unknown Modifier
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 */
public class UnknownModifier implements Modifier, Configurable {

    /**
     * ABNF: name = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." ) ABNF:
     * unknown-modifier = name "=" macro-string
     */
    public static final String REGEX = "(" + SPF1Parser.ALPHA_PATTERN + "{1}"
            + "[A-Za-z0-9\\-\\_\\.]*" + ")" + "\\=("
            + SPF1Parser.MACRO_STRING_REGEX + ")";

    /**
     * @see org.apache.james.jspf.core.Modifier#run(org.apache.james.jspf.core.SPF1Data)
     */
    public String run(SPF1Data spfData) throws PermErrorException {
        return null;
    }

    /**
     * @see org.apache.james.jspf.core.Modifier#enforceSingleInstance()
     */
    public boolean enforceSingleInstance() {
        return false;
    }

    /**
     * @see org.apache.james.jspf.core.Configurable#config(ConfigurationMatch)
     */
    public synchronized void config(ConfigurationMatch params) throws PermErrorException {
        // Nothing to do
    }

}
