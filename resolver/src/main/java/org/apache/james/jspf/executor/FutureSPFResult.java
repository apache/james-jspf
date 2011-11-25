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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.SPFSession;


/**
 * A Blocking version of SPFResult which block until the SPFResult is fully set
 *
 */
public class FutureSPFResult extends SPFResult {
    
    private boolean isReady;
    private List<IFutureSPFResultListener> listeners;
    private int waiters;
    private final Logger log;
    
    public FutureSPFResult() {
        this.log = null;
        isReady = false;
    }
    
    public FutureSPFResult(Logger log) {
        this.log = log;   	
        this.isReady = false;
    }

	/**
     * Set SPFResult using the given SPFsession
     * 
     * @param session 
     * 
     */
    public void setSPFResult(SPFSession session) {
        Iterator<IFutureSPFResultListener> listenerIt = null;
        synchronized (this) {
            if (!isReady) {
                setSPFSession(session);
                isReady = true;
                if (waiters > 0) {
                    notifyAll();
                }
                if (listeners != null) {
                    listenerIt = listeners.iterator();
                    listeners = null;
                }
            }
        }
        if (listenerIt != null) {
            while (listenerIt.hasNext()) {
                IFutureSPFResultListener listener = listenerIt.next();
                try {
                    listener.onSPFResult(this);
                } catch (Throwable e) {
                    // catch exception. See JSPF-95
                    if (log != null) {
                        log.warn("An exception was thrown by the listener " + listener, e);
                    }
                }
            }
            listenerIt = null;
        }
    }

    /**
     * Waits until the SPFResult is set 
     *
     */
    private synchronized void checkReady() {
        while (!isReady) {
            try {
                waiters++;
                wait();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                waiters--;
            }
        }
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getExplanation()
     */
    public String getExplanation() {
        checkReady();
        return super.getExplanation();
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getHeader()
     */
    public String getHeader() {
        checkReady();
        return super.getHeader();
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getHeaderName()
     */
    public String getHeaderName() {
        checkReady();
        return super.getHeaderName();
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getHeaderText()
     */
    public String getHeaderText() {
        checkReady();
        return super.getHeaderText();
    }

    /**
     * @see org.apache.james.jspf.executor.SPFResult#getResult()
     */
    public String getResult() {
        checkReady();
        return super.getResult();
    }

    /**
     * Return true if the result was fully builded 
     * 
     * @return true or false
     */
    public synchronized boolean isReady() {
        return isReady;
    }

    /**
     * Add a {@link IFutureSPFResultListener} which will get notified once {@link #isReady()} returns <code>true</code>
     * 
     * @param listener
     */
    public synchronized void addListener(IFutureSPFResultListener listener) {
        if (!isReady) {
            if (listeners == null) {
                listeners = new ArrayList<IFutureSPFResultListener>();
            }
            listeners.add(listener);
        } else {
            listener.onSPFResult(this);
        }
    }
   
    /**
     * Remove a {@link IFutureSPFResultListener}
     * 
     * @param listener
     */
    public synchronized void removeListener(IFutureSPFResultListener listener) {
        if (!isReady && listeners != null) {
            listeners.remove(listener);
        }
    }
    
    
    /**
     * Listener which will get notified once a {@link FutureSPFResult#isReady()} returns <code>true</code>. So it will not block anymore
     * 
     *
     */
    public interface IFutureSPFResultListener {
        
        /**
         * Get called once a {@link FutureSPFResult} is ready
         * 
         * @param result
         */
        void onSPFResult(FutureSPFResult result);
    }
}
