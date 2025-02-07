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

package org.apache.james.jspf.executor;

import java.io.IOException;
import java.util.ArrayList;
import java.util.concurrent.CompletionException;

import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.DNSResponse;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerExceptionCatcher;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.SPFResultException;
import org.apache.james.jspf.core.exceptions.TempErrorException;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.lookup.NoSuchRRSetException;

/**
 * Asynchronous implementation of SPFExecutor. All queries will get executed asynchronously
 */
public class AsynchronousSPFExecutor implements SPFExecutor {
    private static final Logger LOGGER = LoggerFactory.getLogger(AsynchronousSPFExecutor.class);

    private DNSService dnsProbe;

    public AsynchronousSPFExecutor(DNSService service) {
        this.dnsProbe = service;
    }

    /**
     * @see SPFExecutor#execute(SPFSession, FutureSPFResult)
     */
    public void execute(SPFSession session, FutureSPFResult result) {
        SPFChecker checker = session.popChecker();
        if (checker == null) {
            result.setSPFResult(session);
            return;
        }
        // only execute checkers we added (better recursivity)
        LOGGER.debug("Executing checker: {}", checker);
        try {
            DNSLookupContinuation cont = checker.checkSPF(session);
            handleCont(session, result, cont, checker);
        } catch (Exception e) {
            handleError(session, e);
            result.setSPFResult(session);
        }
    }

    private void handleCont(SPFSession session, FutureSPFResult result, DNSLookupContinuation cont, SPFChecker checker) {
        if (cont != null) {
            // if the checker returns a continuation we return it
            dnsProbe.getRecordsAsync(cont.getRequest())
                .thenAccept(results -> {
                    try {
                        DNSLookupContinuation dnsLookupContinuation = cont.getListener().onDNSResponse(new DNSResponse(results), session);
                        handleCont(session, result, dnsLookupContinuation, checker);
                    } catch (PermErrorException | NoneException | TempErrorException | NeutralException e) {
                        handleError(session, e);
                        result.setSPFResult(session);
                    }
                })
                .exceptionally(e -> {
                    if (e instanceof CompletionException && e.getCause() != null) {
                        e = e.getCause();
                    }
                    if (e instanceof IOException && e.getMessage() != null && e.getMessage().startsWith("Timed out ")) {
                        e = new TimeoutException(e.getMessage());
                    }
                    if (e instanceof NoSuchRRSetException) {
                        try {
                            DNSLookupContinuation dnsLookupContinuation = cont.getListener().onDNSResponse(new DNSResponse(new ArrayList<>()), session);
                            handleCont(session, result, dnsLookupContinuation, checker);
                            result.setSPFResult(session);
                            return null;
                        } catch (PermErrorException | NoneException | TempErrorException | NeutralException ex2) {
                            handleError(session, ex2);
                            result.setSPFResult(session);
                            return null;
                        }
                    }
                    if (e instanceof TimeoutException) {
                        handleTimeout(cont, new DNSResponse((TimeoutException) e), session, result, checker);
                        result.setSPFResult(session);
                        return null;
                    }
                    handleError(session, e);
                    result.setSPFResult(session);
                    return null;
                });
        } else {
            execute(session, result);
        }
    }

    private void handleTimeout(DNSLookupContinuation cont, DNSResponse e, SPFSession session, FutureSPFResult result, SPFChecker checker) {
        try {
            DNSLookupContinuation dnsLookupContinuation = cont.getListener().onDNSResponse(e, session);
            handleCont(session, result, dnsLookupContinuation, checker);
        } catch (PermErrorException | NoneException | TempErrorException | NeutralException ex2) {
            handleError(session, ex2);
        }
    }

    private void handleError(SPFSession session, Throwable e) {
        while (e != null) {
            SPFChecker checker = session.popChecker(c -> c instanceof SPFCheckerExceptionCatcher);
            if (checker == null) {
                // Error case not handled by JSPF. Throw to avoid infinite loop. See JSPF-110.
                throw new RuntimeException("SPFCheckerExceptionCatcher implementation not found, session: " + session, e);
            }
            try {
                ((SPFCheckerExceptionCatcher) checker).onException(e, session);
                e = null;
            } catch (SPFResultException ex) {
                e = ex;
            } catch (Exception ex) {
                LOGGER.error("Error: ", ex);
            }
        }
    }
}
