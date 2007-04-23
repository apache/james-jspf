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

import org.apache.james.jspf.FutureSPFResult;
import org.apache.james.jspf.core.DNSService.TimeoutException;
import org.apache.james.jspf.exceptions.SPFResultException;

/**
 * Synchronous implementation of SPFExecuter. All queries will get executed synchronously
 */
public class SynchronousSPFExecutor implements SPFExecutor {
    
    private Logger log;
    private DNSService dnsProbe;

    public SynchronousSPFExecutor(Logger log, DNSService service) {
        this.log = log;
        this.dnsProbe = service;
    }

    /**
     * @see org.apache.james.jspf.core.SPFExecutor#execute(org.apache.james.jspf.core.SPFSession, org.apache.james.jspf.FutureSPFResult)
     */
    public void execute(SPFSession session, FutureSPFResult result) {
        SPFChecker checker;
        while ((checker = session.popChecker()) != null) {
            // only execute checkers we added (better recursivity)
            log.debug("Executing checker: " + checker);
            try {
                DNSLookupContinuation cont = checker.checkSPF(session);
                // if the checker returns a continuation we return it
                while (cont != null) {
                    DNSResponse response;
                    try {
                        response = new DNSResponse(dnsProbe.getRecords(cont
                                .getRequest().getHostname(), cont.getRequest()
                                .getRecordType()));
                    } catch (TimeoutException e) {
                        response = new DNSResponse(e);
                    }
                    cont = cont.getListener().onDNSResponse(response, session);
                }
            } catch (Exception e) {
                while (e != null) {
                    SPFCheckerExceptionCatcher catcher = session
                            .getExceptionCatcher();
                    try {
                        catcher.onException(e, session);
                        e = null;
                    } catch (SPFResultException ex) {
                        e = ex;
                    }
                }
            }
        }
        result.setSPFResult(session);
    }

}
