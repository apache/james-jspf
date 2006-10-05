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

package org.apache.james.jspf.policies.local;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.policies.AbstractNestedPolicy;

/**
 * Class to support Fallback feature
 */
public class FallbackPolicy extends AbstractNestedPolicy {

    private Map fallBackMap;

    private SPFRecordParser parser;

    private Logger log;

    public FallbackPolicy(Logger log, SPFRecordParser parser) {
        this.log = log;
        fallBackMap = Collections.synchronizedMap(new HashMap());
        this.parser = parser;
    }

    /**
     * Add a fallback entry.
     * 
     * @param rawHost
     *            the host or ipaddress for which the entry should be added.
     * @param rawSpfRecord
     *            the spfRecord to add
     * @throws IllegalArgumentException
     *             get thrown on invalid spfRecord
     */
    public void addFallBackEntry(String rawHost, String rawSpfRecord)
            throws IllegalArgumentException {
        String host;
        try {
            log.debug("Start parsing SPF-Record: " + rawSpfRecord);
            SPF1Record spfRecord = parser.parse(rawSpfRecord);
            if (rawHost.startsWith("*")) {
                host = rawHost.substring(1);
                log.debug("Convert host " + rawHost + " to " + host);
            } else if (rawHost.endsWith("*")) {
                int length = rawHost.length();
                host = rawHost.substring(length - 1, length);
                log.debug("Convert host " + rawHost + " to " + host);
            } else {
                host = rawHost;
            }

            synchronized (fallBackMap) {
                fallBackMap.put(host, spfRecord);
            }
        } catch (PermErrorException e) {
            throw new IllegalArgumentException("Invalid SPF-Record: "
                    + rawSpfRecord);
        } catch (NoneException e) {
            throw new IllegalArgumentException("Invalid SPF-Record: "
                    + rawSpfRecord);
        } catch (NeutralException e) {
            throw new IllegalArgumentException("Invalid SPF-Record: "
                    + rawSpfRecord);
        }

    }

    /**
     * Clear all fallBack entries
     * 
     */
    public void clearFallBackEntrys() {
        log.debug("Clear all fallback entries");
        synchronized (fallBackMap) {
            fallBackMap.clear();
        }
    }

    /**
     * Remove fallBack entry
     * 
     * @param host
     *            The host
     */
    public void removeFallBackEntrys(String host) {
        log.debug("Remove fallback entry for host: " + host);
        synchronized (fallBackMap) {
            fallBackMap.remove(getRawFallBackEntry(host));
        }
    }

    /**
     * @see org.apache.james.jspf.policies.AbstractNestedPolicy#getSPFRecordFallback(java.lang.String)
     */
    public SPF1Record getSPFRecordFallback(String host) {
        return getMySPFRecord(host);
    }
    
    /**
     * Return the SPF1Record for the given host
     * 
     * @param host
     *            the hostname or ipaddress
     * @return the SPF1Record of null if no SPF1Record was found in fallback for
     *         the given host
     */
    protected SPF1Record getMySPFRecord(String host) {
        Object fallBack = null;

        synchronized (fallBackMap) {
            fallBack = getRawFallBackEntry(host);
        }

        if (fallBack != null) {
            return (SPF1Record) fallBack;
        } else {
            return null;
        }
    }

    /**
     * Return the Object stored in the map which match the given host. Keep in
     * mind that this method should only called in a synchronized method or
     * block
     * 
     * @param host
     *            the host
     * @return the stored object for the given host or null
     */
    private Object getRawFallBackEntry(String host) {
        Iterator fallBackIt = fallBackMap.keySet().iterator();

        while (fallBackIt.hasNext()) {
            String rawHost = fallBackIt.next().toString();

            if ((rawHost.startsWith(".") && host.startsWith(rawHost))
                    || rawHost.endsWith(".") && host.endsWith(rawHost)) {
                return fallBackMap.get(rawHost);
            }
        }
        return null;
    }

}
