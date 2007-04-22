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

package org.apache.james.jspf;

import org.apache.james.jspf.core.SPFSession;

public class FutureSPFResult extends SPFResult {
    
    boolean isReady;
    
    public FutureSPFResult() {
        isReady = false;
    }
    
    public synchronized void setSPFResult(SPFSession session) {
        setSPFSession(session);
        isReady = true;
        notify();
    }

    private synchronized void checkReady() {
        while (!isReady) {
            try {
                wait();
            } catch (InterruptedException e) {
                //
            }
        }
    }

    public String getExplanation() {
        checkReady();
        return super.getExplanation();
    }

    public String getHeader() {
        checkReady();
        return super.getHeader();
    }

    public String getHeaderName() {
        checkReady();
        return super.getHeaderName();
    }

    public String getHeaderText() {
        checkReady();
        return super.getHeaderText();
    }

    public String getResult() {
        checkReady();
        return super.getResult();
    }

    public boolean isReady() {
        return isReady;
    }
    

}
