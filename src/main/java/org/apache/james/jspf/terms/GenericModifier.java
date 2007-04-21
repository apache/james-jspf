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


package org.apache.james.jspf.terms;

import org.apache.james.jspf.core.Configurable;
import org.apache.james.jspf.core.Configuration;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.Modifier;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.wiring.LogEnabled;

/**
 * This abstract class represent a gerneric modifier
 * 
 */
public abstract class GenericModifier implements Modifier, Configurable, LogEnabled {

    private String host;

    protected Logger log;

    /**
     * @see org.apache.james.jspf.core.Modifier#run(SPFSession)
     * 
     */
    public void checkSPF(SPFSession spfData) throws PermErrorException,
            TempErrorException {
        log.debug("Processing modifier: " + this);
        checkSPFLogged(spfData);
        log.debug("Processed modifier: " + this + " resulted in "
                + spfData.getCurrentResult());
    }
    
    protected abstract void checkSPFLogged(SPFSession spfData) throws PermErrorException,
        TempErrorException;


    /**
     * @see org.apache.james.jspf.core.Modifier#enforceSingleInstance()
     */
    public boolean enforceSingleInstance() {
        return true;
    }

    /**
     * @see org.apache.james.jspf.core.Configurable#config(Configuration)
     */
    public synchronized void config(Configuration params) throws PermErrorException {
        if (params.groupCount() > 0) {
            this.host = params.group(1);
        }
    }

    /**
     * @return Returns the host.
     */
    protected synchronized String getHost() {
        return host;
    }
    

    /**
     * @see org.apache.james.jspf.wiring.LogEnabled#enableLogging(org.apache.james.jspf.core.Logger)
     */
    public void enableLogging(Logger logger) {
        this.log = logger;
    }


}
