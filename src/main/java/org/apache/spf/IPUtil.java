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

import java.util.List;

import org.apache.spf.util.IPAddr;

public class IPUtil {
    
    /**
     * Check if the given ipaddress array contains the provided ip.
     * 
     * @param checkAddress
     *            The ip wich should be contained in the given ArrayList
     * @param addressList
     *            The ip ArrayList.
     * @return true or false
     */
    public static boolean checkAddressList(IPAddr checkAddress, List addressList) {

        IPAddr aValue = null;
        for (int i = 0; i < addressList.size(); i++) {

            aValue = (IPAddr) addressList.get(i);

            if (checkAddress.getMaskedIPAddress().equals(
                    aValue.getMaskedIPAddress())) {
                return true;
            }
        }
        return false;
    }

}
