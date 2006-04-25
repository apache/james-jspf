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
 * This Class is used to get an Array of reserverd MX-Records.
 * .
 * @author MimeCast
 * @author Norman Maurer <nm@byteaction.de> @since 0.3
 * 
 */
public class ReservedMX {

	private static ArrayList reservedAddresses = new ArrayList();

	static {

		try {
			reservedAddresses.add(IPAddr.getAddress("0.0.0.0", 8));
			reservedAddresses.add(IPAddr.getAddress("10.0.0.0", 8));
			reservedAddresses.add(IPAddr.getAddress("127.0.0.0", 8));
			reservedAddresses.add(IPAddr.getAddress("169.254.0.0", 16));
			reservedAddresses.add(IPAddr.getAddress("172.16.0.0", 12));
			reservedAddresses.add(IPAddr.getAddress("192.88.99.0", 24));
			reservedAddresses.add(IPAddr.getAddress("192.0.2.0", 24));
			reservedAddresses.add(IPAddr.getAddress("192.168.0.0", 16));
			reservedAddresses.add(IPAddr.getAddress("192.18.0.0", 15));
			reservedAddresses.add(IPAddr.getAddress("224.0.0.0", 4));
			reservedAddresses.add(IPAddr.getAddress("240.0.0.0", 4));

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * Check if an ipaddress is reserved
	 * 
	 * @param ipAddress The ipAddress which should be checked
	 * @return true or false
	 */
	public static boolean isReserved(String ipAddress) {

		boolean isReserved = false;

		try {
			isReserved = isReserved(IPAddr.getAddress(ipAddress, 32));
		} catch (Exception e) {
		}
		return isReserved;

	}

	/**
	 *
	 * @see #isReserved(String)
	 */
	public static boolean isReserved(IPAddr testAddress) {

		IPAddr reservedCompare;

		for (int i = 0; i < reservedAddresses.size(); i++) {
			reservedCompare = (IPAddr) reservedAddresses.get(i);
			testAddress.setMask(reservedCompare.getMaskLength());
			if (testAddress.getMaskedIPAddress().equals(
					reservedCompare.getMaskedIPAddress())) {
				return true;
			}
		}

		return false;

	}

}