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

package org.apache.james.jspf.impl;

import org.apache.james.jspf.core.DNSAsynchLookupService;
import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IResponseImpl;
import org.apache.james.jspf.core.IResponseQueue;
import org.apache.james.jspf.core.DNSService.TimeoutException;

import java.util.LinkedList;

public class DNSServiceAsynchSimulator implements Runnable, DNSAsynchLookupService {

    private DNSService dnsService;
    private Thread worker;
    private LinkedList queue;
    private int waitingThreads = 0;
    
    public static final class Request {
        private final DNSRequest value;
        private final Object id;
        private final IResponseQueue responseQueue;
        public Request(DNSRequest value, Object id, IResponseQueue responseQueue) {
            this.value = value;
            this.id = id;
            this.responseQueue = responseQueue;
        }
        public DNSRequest getValue() {
            return value;
        }
        public Object getId() {
            return id;
        }
        public IResponseQueue getResponseQueue() {
            return responseQueue;
        }
        
    }

    public DNSServiceAsynchSimulator(DNSService service) {
        this.dnsService = service;

        this.queue = new LinkedList();
        this.worker = new Thread(this);
        this.worker.setDaemon(true);
        this.worker.setName("SPFExecutor");
        this.worker.start();

    }

    /**
     * @see org.apache.james.jspf.core.DNSService#getRecordsAsynch(java.lang.String, int, java.lang.Object, org.apache.james.jspf.core.IResponseQueue)
     */
    public void getRecordsAsynch(DNSRequest request, Object id,
            final IResponseQueue responsePool) {
        
        synchronized (queue) {
            queue.addLast(new Request(request, id, responsePool));
            queue.notify();
        }
        
    }

    public void run() {
        while (true) {
            Request req;
            synchronized (queue) {
                if ( (queue.size() - waitingThreads <= 0) ) {
                    try {
                        waitingThreads++; queue.wait();
                    } catch (InterruptedException e) {
                        Thread.interrupted();
                    }
                    waitingThreads--;
                }
                req = (Request) queue.removeFirst();
            }
            
            IResponseImpl response;
            try {
                response = new IResponseImpl(req.getId(), dnsService.getRecords(req.getValue()));
            } catch (TimeoutException e) {
                response = new IResponseImpl(req.getId(), e);
            }

            req.getResponseQueue().insertResponse(response);
        }
    }

}
