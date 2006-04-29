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

import org.apache.spf.MacroExpand;
import org.apache.spf.SPF1Data;

public class ExpMechanism {

    private String host = null;

    /**
     * @param host The hostname or ip
     */
    public void init(String host) {
        this.host = host;
    }

    /**
     * Generate the explanation and set it in SPF1Data so it can be accessed easy later if needed
     * @param spfData The SPF1Data which should used
     */
    public void run(SPF1Data spfData) {
        String exp = null;
        String host = this.host;
        try {
            host = new MacroExpand(spfData).expandDomain(host);
            exp = spfData.getDnsProbe().getTxtCatType(host);

        } catch (Exception e) {
        }

        if ((exp == null) || (exp.equals(""))) {
            exp = "http://www.openspf.org/why.html?sender=%{S}&ip=%{I}";
        }

        try {
            spfData.setExplanation(new MacroExpand(spfData)
                    .expandExplanation(exp));
        } catch (Exception e) {
            spfData.setExplanation("");
        }
    }

}
