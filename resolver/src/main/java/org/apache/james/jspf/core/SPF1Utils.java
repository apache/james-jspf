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

import org.apache.james.jspf.core.exceptions.SPFErrorConstants;


/**
 * 
 * Class that offer static methods to convert SPF Results and contains all
 * possible results as static Strings.
 *
 */

public class SPF1Utils {

    public static final String DEFAULT_EXPLANATION = "http://www.openspf.org/why.html?sender=%{S}&ip=%{I}";
    public static final String BEST_GUESS_RECORD = "v=spf1 a/24 mx/24 ptr ?all";
    public static final String ATTRIBUTE_SPF1_RECORD = "SPF.SPF1Record";

    /**
     * Convert raw SPF results to SPF names
     * 
     * @param result The result which should converted
     * @return coverted result
     */
    public static String resultToName(String result) {

        if (result.equals(SPF1Constants.PASS)) {
            return SPFErrorConstants.PASS_CONV;
        } else if (result.equals(SPF1Constants.FAIL)) {
            return SPFErrorConstants.FAIL_CONV;
        } else if (result.equals(SPF1Constants.NEUTRAL)) {
            return SPFErrorConstants.NEUTRAL_CONV;
        } else if (result.equals(SPF1Constants.SOFTFAIL)) {
            return SPFErrorConstants.SOFTFAIL_CONV;
        } else {
            return SPFErrorConstants.NEUTRAL_CONV;
        }

    }

    /**
     * Check for valid FQDN
     * 
     * @param host The hostname to check
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
