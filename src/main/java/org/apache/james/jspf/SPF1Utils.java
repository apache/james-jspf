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

package org.apache.james.jspf;

import org.apache.james.jspf.core.SPF1Constants;

/**
 * 
 * Class that offer static methods to convert SPF Results and contains all
 * possible results as static Strings.
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 */

public class SPF1Utils {
    public static final String PERM_ERROR = "error";

    public static final String PERM_ERROR_CONV = "error";

    public static final String NONE = "none";

    public static final String NONE_CONV = "none";

    public static final String TEMP_ERROR = "temperror";

    public static final String TEMP_ERROR_CONV = "temperror";

    public static final String PASS_CONV = "pass";

    public static final String NEUTRAL_CONV = "neutral";

    public static final String FAIL_CONV = "fail";

    public static final String SOFTFAIL_CONV = "softfail";
    
    public static final String DEFAULT_EXPLANATION = "http://www.openspf.org/why.html?sender=%{S}&ip=%{I}";

    /**
     * Convert raw SPF results to SPF names
     * 
     * @param result
     *            The result which should converted
     * @return coverted result
     */
    protected static String resultToName(String result) {

        if (result.equals(SPF1Constants.PASS)) {
            return PASS_CONV;
        } else if (result.equals(SPF1Constants.FAIL)) {
            return FAIL_CONV;
        } else if (result.equals(SPF1Constants.NEUTRAL)) {
            return NEUTRAL_CONV;
        } else if (result.equals(SPF1Constants.SOFTFAIL)) {
            return SOFTFAIL_CONV;
        } else if (result.equals(PERM_ERROR)) {
            return PERM_ERROR_CONV;
        } else if (result.equals(TEMP_ERROR)) {
            return TEMP_ERROR_CONV;
        } else if (result.equals(NONE)) {
            return NONE_CONV;
        } else {
            return NEUTRAL_CONV;
        }

    }

    /**
     * Covert SPF names to raw SPF results
     * 
     * @param result
     *            The result which should converted
     * @return coverted result
     */
    protected static String nameToResult(String result) {

        if (result.equals(PASS_CONV)) {
            return SPF1Constants.PASS;
        } else if (result.equals(FAIL_CONV)) {
            return SPF1Constants.FAIL;
        } else if (result.equals(NEUTRAL_CONV)) {
            return SPF1Constants.NEUTRAL;
        } else if (result.equals(SOFTFAIL_CONV)) {
            return SPF1Constants.SOFTFAIL;
        } else if (result.equals(PERM_ERROR_CONV)) {
            return PERM_ERROR;
        } else if (result.equals(TEMP_ERROR_CONV)) {
            return TEMP_ERROR;
        } else if (result.equals(NONE_CONV)) {
            return NONE;
        } else {
            return SPF1Constants.NEUTRAL;
        }

    }

    /**
     * Check for valid FQDN
     * 
     * @param host
     *            The hostname to check
     * @return false or true
     */
    public static boolean checkFQDN(String host) {
        String regex = "(([a-zA-Z0-9\\-])+\\.)+([a-zA-Z]+)$";
        if (host.matches(regex)) {
            return true;
        } else {
            return false;
        }
    }

}
