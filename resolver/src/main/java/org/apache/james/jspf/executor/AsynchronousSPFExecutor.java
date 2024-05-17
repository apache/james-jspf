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

import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
import org.apache.james.jspf.policies.SPFRetriever;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Synchronous implementation of SPFExecuter. All queries will get executed synchronously
 */
public class AsynchronousSPFExecutor implements SPFExecutor {
    Set<Class<SPFRetriever>> UN_SUPPORTED_ASYNC_CHECKERS = Stream.of(SPFRetriever.class)
        .collect(Collectors.toSet());

    private static final Logger LOGGER = LoggerFactory.getLogger(AsynchronousSPFExecutor.class);

    private DNSService dnsProbe;

    public AsynchronousSPFExecutor(DNSService service) {
        this.dnsProbe = service;
    }

    /**
     * @see SPFExecutor#execute(SPFSession, FutureSPFResult)
     */
    public void execute(SPFSession session, FutureSPFResult result) {
        SPFChecker checker;
        while ((checker = session.popChecker()) != null) {
            // only execute checkers we added (better recursivity)
            LOGGER.debug("Executing checker: {}", checker);
            try {
                DNSLookupContinuation cont = checker.checkSPF(session);
                if (cont == null) {
                    continue;
                }
                doGetRecord(session, cont, checker);
            } catch (Exception e) {
                handleError(session, checker, e);
            }
        }
        result.setSPFResult(session);
    }

    private void doGetRecord(SPFSession session, DNSLookupContinuation cont, SPFChecker finalChecker) {
        // if the checker returns a continuation we return it
        CompletionStage<Void> completionStage = dnsProbe.getRecordsAsync(cont.getRequest())
            .thenAccept(results -> {
                try {
                    DNSLookupContinuation lookupContinuation = cont.getListener().onDNSResponse(new DNSResponse(results), session);
                    if (lookupContinuation != null) {
                        doGetRecord(session, lookupContinuation, finalChecker);
                    }
                } catch (PermErrorException | NoneException | TempErrorException | NeutralException e) {
                    handleError(session, finalChecker, e);
                }
            })
            .exceptionally(e -> {
                if (e instanceof TimeoutException) {
                    handleTimeout(session, finalChecker, cont, (TimeoutException) e);
                }
                if (e.getCause() instanceof TimeoutException) {
                    handleTimeout(session, finalChecker, cont, (TimeoutException) e.getCause());
                }
                return null;
            });

        if (UN_SUPPORTED_ASYNC_CHECKERS.contains(finalChecker.getClass())) {
            try {
                completionStage.toCompletableFuture().get();
            } catch (InterruptedException | ExecutionException e) {
                throw new RuntimeException("Error while executing async checker", e);
            }
        }
    }

    private void handleTimeout(SPFSession session, SPFChecker finalChecker, DNSLookupContinuation cont, TimeoutException e) {
        try {
            cont.getListener().onDNSResponse(new DNSResponse(e), session);
        } catch (PermErrorException | NoneException | TempErrorException | NeutralException ex2) {
            handleError(session, finalChecker, ex2);
        }
    }

    private void handleError(SPFSession session, SPFChecker checker, Exception e) {
        while (e != null) {
            while (checker == null || !(checker instanceof SPFCheckerExceptionCatcher)) {
                checker = session.popChecker();
            }
            try {
                ((SPFCheckerExceptionCatcher) checker).onException(e, session);
                e = null;
            } catch (SPFResultException ex) {
                e = ex;
            } finally {
                checker = null;
            }
        }
    }
}
