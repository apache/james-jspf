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
import org.apache.james.jspf.exceptions.SPFResultException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.policies.AbstractNestedPolicy;

/**
 * Class to support Fallback feature
 */
public class FallbackPolicy extends AbstractNestedPolicy {

    private Map entryMap;

    private SPFRecordParser parser;

    private Logger log;

    public FallbackPolicy(Logger log, SPFRecordParser parser) {
        this.log = log;
        entryMap = Collections.synchronizedMap(new HashMap());
        this.parser = parser;
    }

    /**
     * Add a entry.
     * 
     * @param rawHost
     *            the host or ipaddress for which the entry should be added.
     * @param rawSpfRecord
     *            the spfRecord to add
     * @throws IllegalArgumentException
     *             get thrown on invalid spfRecord
     */
    public void addEntry(String rawHost, String rawSpfRecord)
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

            synchronized (entryMap) {
                entryMap.put(host, spfRecord);
            }
        } catch (SPFResultException e) {
            throw new IllegalArgumentException("Invalid SPF-Record: "
                    + rawSpfRecord);
        }

    }

    /**
     * Clear all entries
     * 
     */
    public void clearEntrys() {
        log.debug("Clear all entries");
        synchronized (entryMap) {
            entryMap.clear();
        }
    }

    /**
     * Remove entry
     * 
     * @param host
     *            The host
     */
    public void removeEntry(String host) {
        log.debug("Remove fallback entry for host: " + host);
        synchronized (entryMap) {
            entryMap.remove(getRawEntry(host));
        }
    }

    /**
     * @see org.apache.james.jspf.policies.AbstractNestedPolicy#getSPFRecordPostFilter(java.lang.String, org.apache.james.jspf.core.SPF1Record)
     */
    protected SPF1Record getSPFRecordPostFilter(String currentDomain, SPF1Record res) throws PermErrorException, TempErrorException, NoneException, NeutralException {
        if (res == null) {
            return getMySPFRecord(currentDomain);
        } else {
            return res;
        }
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
        Object entry = null;

        synchronized (entryMap) {
            entry = getRawEntry(host);
        }

        if (entry != null) {
            return (SPF1Record) entry;
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
    private Object getRawEntry(String host) {
        Iterator fallBackIt = entryMap.keySet().iterator();

        while (fallBackIt.hasNext()) {
            String rawHost = fallBackIt.next().toString();

            if ((rawHost.startsWith(".") && host.startsWith(rawHost))
                    || rawHost.endsWith(".") && host.endsWith(rawHost)) {
                return entryMap.get(rawHost);
            }
        }
        return null;
    }

}
