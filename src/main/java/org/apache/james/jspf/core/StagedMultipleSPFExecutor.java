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

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

/**
 * Async implementation of SPFExecutor
 *
 */
public class StagedMultipleSPFExecutor implements SPFExecutor, Runnable {

    private static final String ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION = "StagedMultipleSPFExecutor.continuation";

    private static class ResponseQueueImpl extends LinkedList implements IResponseQueue {

        private int waitingThreads = 0;

        /**
         * @see org.apache.james.jspf.core.IResponseQueue#insertResponse(org.apache.james.jspf.core.IResponse)
         */
        public synchronized void insertResponse(IResponse r) {
            addLast(r);
            notify();
        }

        /**
         * @see org.apache.james.jspf.core.IResponseQueue#removeResponse()
         */
        public synchronized IResponse removeResponse() {
            if ( isEmpty() ) {
                try { waitingThreads++; wait();}
                catch (InterruptedException e)  {Thread.interrupted();}
                waitingThreads--;
            }
            return (IResponse)removeFirst();        }

        /**
         * @see java.util.AbstractCollection#isEmpty()
         */
        public boolean isEmpty() {
            return  (size() - waitingThreads <= 0);
        }

    }

    private Logger log;
    private DNSService dnsProbe;
    private Thread worker;
    private Map sessions;
    private ResponseQueueImpl responseQueue;

    public StagedMultipleSPFExecutor(Logger log, DNSService service) {
        this.log = log;
        this.dnsProbe = service;

        this.responseQueue = new ResponseQueueImpl();

        this.sessions = new HashMap();

        this.worker = new Thread(this);
        this.worker.setDaemon(true);
        this.worker.setName("SPFExecutor");
        this.worker.start();
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
                if (cont != null) {
                    dnsProbe.getRecordsAsynch(cont.getRequest().getHostname(), cont.getRequest().getRecordType(), session, responseQueue);
                    session.setAttribute(ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION, cont);
                    sessions.put(session, result);
                    return;
                } else {
                    sessions.remove(sessions);
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
        System.out.println("================> RESULT!!!!!");
        result.setSPFResult(session);
    }

    public void run() {

        while (true) {
            IResponse resp = responseQueue.removeResponse();
            
            SPFSession session = (SPFSession) resp.getId();
            FutureSPFResult result = (FutureSPFResult) sessions.get(resp.getId());
            sessions.remove(session);
            DNSLookupContinuation cont = (DNSLookupContinuation) session.getAttribute(ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION);
            
            DNSResponse response;
            if (resp.getException() != null) {
                response = new DNSResponse((TimeoutException) resp.getException());
            } else {
                response = new DNSResponse((List) resp.getValue());
            }
            
            
            try {
                cont = cont.getListener().onDNSResponse(response, session);
                
                if (cont != null) {
                    dnsProbe.getRecordsAsynch(cont.getRequest().getHostname(), cont.getRequest().getRecordType(), session, responseQueue);
                    session.setAttribute(ATTRIBUTE_STAGED_EXECUTOR_CONTINUATION, cont);
                    sessions.put(session, result);
                } else {
                    execute(session, result);
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
                execute(session, result);
            }
        }
    }

}
