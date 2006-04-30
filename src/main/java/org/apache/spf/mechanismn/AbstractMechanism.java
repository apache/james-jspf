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

package org.apache.spf.mechanismn;

import org.apache.spf.PermErrorException;
import org.apache.spf.SPF1Data;

import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class AbstractMechanism implements Mechanism {

    protected Pattern namePattern;

    protected Pattern valuePattern;

    public void init(String value) throws PermErrorException {
        if (value == null) {
            value = "";
        }
        if ((value == null || value.length() == 0)
                && valuePattern.pattern().length() == 0) {
            config(null);
        } else {

            Matcher m = valuePattern.matcher(value);
            if (!m.matches()) {
                throw new PermErrorException("Value does not match: "
                        + valuePattern.pattern() + " " + value);
            }
            config(m.toMatchResult());
        }
    }

    public AbstractMechanism(String name, String value) {
        namePattern = Pattern.compile(name);
        valuePattern = Pattern.compile(value);
    }

    /**
     * Run the mechanismn with the give SPF1Data
     * 
     * @param spfData
     *            The SPF1Data
     * @return result If the not match it return null. Otherwise it returns the
     *         modifier
     * @throws PermErrorException
     *             if somethink strange happen
     */
    public abstract boolean run(SPF1Data spfData) throws PermErrorException;

    public abstract void config(MatchResult params) throws PermErrorException;

}
