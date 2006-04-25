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

package org.apache.spf;

import java.util.ArrayList;

/**
 * 
 * Class that offer static methods to convert SPF Results and contains all
 * possible results as static Strings.
 * 
 * @author Mimecast Contact : spf@mimecast.net
 * @author Norman Maurer <nm@byteaction.de>
 */

public class SPF1Utils {
	public static final String PASS = "+";

	public static final String ALLOW = "+";

	public static final String NEUTRAL = "?";

	public static final String FAIL = "-";

	public static final String DENY = "-";

	public static final String SOFTFAIL = "~";

	public static final String ERROR = "error";

	public static final String NONE = "none";
	
	public static final String UNKNOWN = "unknown";

	public static final String PASS_CONV = "pass";

	public static final String ALLOW_CONV = "pass";

	public static final String NEUTRAL_CONV = "neutral";

	public static final String FAIL_CONV = "fail";

	public static final String DENY_CONV = "deny";

	public static final String SOFTFAIL_CONV = "softfail";

	public static final String ERROR_CONV = "error";

	public static final String NONE_CONV = "none";
	
	public static final String UNKNOWN_CONV = "unknown";
	


	/**
	 * Convert raw SPF results to SPF names
	 * 
	 * @param result The result which should converted
	 * @return coverted result
	 */
	protected static String resultToName(String result) {

		if (result.equals(PASS)) {
			return PASS_CONV;
		} else if (result.equals(FAIL)) {
			return FAIL_CONV;
		} else if (result.equals(NEUTRAL)) {
			return NEUTRAL_CONV;
		} else if (result.equals(SOFTFAIL)) {
			return SOFTFAIL_CONV;
		} else if (result.equals(ERROR)) {
			return ERROR_CONV;
		} else if (result.equals(NONE)) {
			return NONE_CONV;
		} else if (result.equals(UNKNOWN)) {
			return UNKNOWN;
		} else {
			return NEUTRAL_CONV;
		}

	}

	/**
	 * Covert SPF names to raw SPF results
	 * 
	 * @param result The result which should converted
	 * @return coverted result
	 */
	protected static String nameToResult(String result) {

		if (result.equals(PASS_CONV)) {
			return PASS;
		} else if (result.equals(ALLOW_CONV)) {
			return ALLOW;
		} else if (result.equals(FAIL_CONV)) {
			return FAIL;
		} else if (result.equals(DENY_CONV)) {
			return DENY;
		} else if (result.equals(NEUTRAL_CONV)) {
			return NEUTRAL;
		} else if (result.equals(SOFTFAIL_CONV)) {
			return SOFTFAIL;
		} else if (result.equals(ERROR_CONV)) {
			return ERROR;
		} else if (result.equals(NONE_CONV)) {
			return NONE;
		} else if (result.equals(UNKNOWN_CONV)) {
			return UNKNOWN;
		} else {
			return NEUTRAL;
		}

	}

	/**
	 * Check for valid FQDN
	 * @param host The hostname to check
	 * @return false or true
	 */
	protected static boolean checkFQDN(String host) {
		String regex = "(([a-zA-Z0-9\\-])+\\.)+([a-zA-Z0-9]{1,4})+$";
		if (host.matches(regex)) {
			return true;
		} else {
			return false;
		}		
	}

}
