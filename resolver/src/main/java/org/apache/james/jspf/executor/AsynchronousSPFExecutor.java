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
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.apache.james.jspf.core.exceptions.SPFResultException;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.lookup.LookupFailedException;

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
            handleErrorAndComplete(session, result, e);
        }
    }

    private void handleCont(SPFSession session, FutureSPFResult result, DNSLookupContinuation cont, SPFChecker checker) {
        if (cont != null) {
            // if the checker returns a continuation we return it
            dnsProbe.getRecordsAsync(cont.getRequest())
                .thenAccept(results -> onResponse(session, result, cont, new DNSResponse(results), checker))
                .exceptionally(e -> {
                    if (e instanceof CompletionException && e.getCause() != null) {
                        e = e.getCause();
                    }
                    if (e instanceof IOException && e.getMessage() != null && e.getMessage().startsWith("Timed out ")) {
                        e = new TimeoutException(e.getMessage());
                    }
                    if (e instanceof LookupFailedException) {
                        onResponse(session, result, cont, new DNSResponse(new ArrayList<>()), checker);
                    } else if (e instanceof TimeoutException) {
                        onResponse(session, result, cont, new DNSResponse((TimeoutException) e), checker);
                    } else {
                        handleErrorAndComplete(session, result, e);
                    }
                    return null;
                });
        } else {
            execute(session, result);
        }
    }

    private void onResponse(SPFSession session, FutureSPFResult result, DNSLookupContinuation cont, DNSResponse response, SPFChecker checker) {
        try {
            DNSLookupContinuation dnsLookupContinuation = cont.getListener().onDNSResponse(response, session);
            // The result is set once no checker is left, or by the error handling
            handleCont(session, result, dnsLookupContinuation, checker);
        } catch (Exception e) {
            handleErrorAndComplete(session, result, e);
        }
    }

    private void handleErrorAndComplete(SPFSession session, FutureSPFResult result, Throwable e) {
        try {
            handleError(session, e);
        } catch (RuntimeException ex) {
            // Never leave the future pending: an unexpected error is a temperror
            LOGGER.error("Unexpected error during the asynchronous SPF check", ex);
            session.setCurrentResult(SPFErrorConstants.TEMP_ERROR_CONV);
            session.setCurrentResultExpanded(SPFErrorConstants.TEMP_ERROR_CONV);
        } finally {
            result.setSPFResult(session);
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
