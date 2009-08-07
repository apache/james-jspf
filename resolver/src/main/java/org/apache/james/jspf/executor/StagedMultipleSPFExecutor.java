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

import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.DNSResponse;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerExceptionCatcher;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.exceptions.SPFResultException;
import org.apache.james.jspf.core.exceptions.TimeoutException;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * Async implementation of SPFExecutor
 *
 */
public class StagedMultipleSPFExecutor implements SPFExecutor, Runnable {

    private static final String ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION = "StagedMultipleSPFExecutor.continuation";

    private static class ResponseQueueImpl extends LinkedList<IResponse> implements IResponseQueue {

        private static final long serialVersionUID = 5714025260393791651L;
        
        private int waitingThreads = 0;

        /**
         * @see org.apache.james.jspf.executor.IResponseQueue#insertResponse(org.apache.james.jspf.executor.IResponse)
         */
        public synchronized void insertResponse(IResponse r) {
            addLast(r);
            notify();
        }

        /**
         * @see org.apache.james.jspf.executor.IResponseQueue#removeResponse()
         */
        public synchronized IResponse removeResponse() {
            if ( (size() - waitingThreads <= 0) ) {
                try { waitingThreads++; wait();}
                catch (InterruptedException e)  {Thread.interrupted();}
                waitingThreads--;
            }
            return (IResponse)removeFirst();        }

    }

    // Use short as id because the id header is limited to 16 bit
    // From RFC1035 4.1.1. Header section format :
    // 
    // ID              A 16 bit identifier assigned by the program that
    //                 generates any kind of query.  This identifier is copied
    //                 the corresponding reply and can be used by the requester
    //                 to match up replies to outstanding queries.
    //
    private static short id;
    
    private synchronized int nextId() {
        return id++;
    }
    
    private Logger log;
    private DNSAsynchLookupService dnsProbe;
    private Thread worker;
    private Map<Integer,SPFSession> sessions;
    private Map<Integer,FutureSPFResult>results;
    private ResponseQueueImpl responseQueue;

    public StagedMultipleSPFExecutor(Logger log, DNSAsynchLookupService service) {
        this.log = log;
        this.dnsProbe = service;

        this.responseQueue = new ResponseQueueImpl();

        this.sessions = Collections.synchronizedMap(new HashMap<Integer,SPFSession>());
        this.results = Collections.synchronizedMap(new HashMap<Integer,FutureSPFResult>());

        this.worker = new Thread(this);
        this.worker.setDaemon(true);
        this.worker.setName("SPFExecutor");
        this.worker.start();
    }

    /**
     * Execute the non-blocking part of the processing and returns.
     * If the working queue is full (50 pending responses) this method will not return
     * until the queue is again not full.
     * 
     * @see org.apache.james.jspf.executor.SPFExecutor#execute(org.apache.james.jspf.core.SPFSession, org.apache.james.jspf.executor.FutureSPFResult)
     */
    public void execute(SPFSession session, FutureSPFResult result) {
        execute(session, result, true);
    }
        
    public void execute(SPFSession session, FutureSPFResult result, boolean throttle) {
        SPFChecker checker;
        while ((checker = session.popChecker()) != null) {
            // only execute checkers we added (better recursivity)
            log.debug("Executing checker: " + checker);
            try {
                DNSLookupContinuation cont = checker.checkSPF(session);
                // if the checker returns a continuation we return it
                if (cont != null) {
                    invokeAsynchService(session, result, cont, throttle);
                    return;
                }
            } catch (Exception e) {
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
        result.setSPFResult(session);
    }

    /**
     * throttle should be true only when the caller thread is the client and not the worker thread.
     * We could even remove the throttle parameter and check the currentThread.
     * This way the worker is never "blocked" while outside callers will be blocked if our
     * queue is too big (so this is not fully "asynchronous").
     */
    private synchronized void invokeAsynchService(SPFSession session,
            FutureSPFResult result, DNSLookupContinuation cont, boolean throttle) {
        while (throttle && results.size() > 50) {
            try {
                this.wait(100);
            } catch (InterruptedException e) {
            }
        }
        int nextId = nextId();
        sessions.put(new Integer(nextId), session);
        results.put(new Integer(nextId), result);
        session.setAttribute(ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION, cont);
        dnsProbe.getRecordsAsynch(cont.getRequest(), nextId, responseQueue);
    }

    public void run() {

        while (true) {
            
            IResponse resp = responseQueue.removeResponse();
            
            Integer respId = (Integer)resp.getId();
            SPFSession session = sessions.remove(respId);
            FutureSPFResult result = results.remove(respId);
            
            DNSLookupContinuation cont = (DNSLookupContinuation) session.getAttribute(ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION);
            
            DNSResponse response;
            if (resp.getException() != null) {
                response = new DNSResponse((TimeoutException) resp.getException());
            } else {
                response = new DNSResponse(resp.getValue());
            }
            
            
            try {
                cont = cont.getListener().onDNSResponse(response, session);
                
                if (cont != null) {
                    invokeAsynchService(session, result, cont, false);
                } else {
                    execute(session, result, false);
                }

            } catch (Exception e) {
                SPFChecker checker = null;
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
                execute(session, result, false);
            }
        }
    }

}
