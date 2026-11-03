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
import java.util.Comparator;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.SPFResultException;
import org.apache.james.jspf.core.exceptions.TempErrorException;
import org.apache.james.jspf.policies.PolicyPostFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;

/**
 * Class to support Fallback feature
 */
public class FallbackPolicy implements PolicyPostFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(FallbackPolicy.class);

    /**
     * @param record the record of an entry
     * @return a record of the same terms, for one check: the policies after this one add their
     *         modifiers to the record they get
     */
    private static SPF1Record copyOf(SPF1Record record) {
        SPF1Record copy = new SPF1Record(record.getRecord());
        copy.getDirectives().addAll(record.getDirectives());
        copy.getModifiers().addAll(record.getModifiers());
        return copy;
    }

    /**
     * @param host a host, or the host of an entry
     * @return the host as domain names compare: in lower case, without its trailing dot, and with
     *         its escapes read (ex\097mple.com is example.com, a dot inside a label stays \.)
     */
    private static String normalize(String host) {
        try {
            Name name = Name.fromString(host, Name.root);
            // the root without its dot, as the text below
            return name.equals(Name.root) ? "" : name.canonicalize().toString(true);
        } catch (TextParseException e) {
            // no domain name: compared as text
            String name = host.toLowerCase(Locale.ROOT);
            return name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        }
    }

    /**
     * @param host a normalized host
     * @param domain a normalized domain
     * @return true if the host is a domain under the domain, label by label: the dot before the
     *         domain separates labels, it is not escaped (mail\.example.com is not under example.com)
     */
    private static boolean isUnder(String host, String domain) {
        int dot = host.length() - domain.length() - 1;
        if (dot < 0 || !host.endsWith(domain) || host.charAt(dot) != '.') {
            return false;
        }
        int backslashes = 0;
        while (backslashes < dot && host.charAt(dot - 1 - backslashes) == '\\') {
            backslashes++;
        }
        return backslashes % 2 == 0;
    }

    /**
     * @param entryHost the normalized host of an entry
     * @param host a normalized host
     * @return true if the entry is for the host
     */
    private static boolean matches(String entryHost, String host) {
        if (entryHost.startsWith("*.")) {
            return isUnder(host, entryHost.substring(2));
        } else if (entryHost.startsWith("*")) {
            return host.endsWith(entryHost.substring(1));
        } else if (entryHost.endsWith("*")) {
            return host.startsWith(entryHost.substring(0, entryHost.length() - 1));
        } else {
            return host.equals(entryHost);
        }
    }

    private Map<String,SPF1Record> entryMap;

    private SPFRecordParser parser;

    public FallbackPolicy(SPFRecordParser parser) {
        entryMap = Collections.synchronizedMap(new HashMap<String,SPF1Record>());
        this.parser = parser;
    }

    /**
     * Add a entry.
     * 
     * @param rawHost
     *            the host for which the entry should be added: a domain (example.com), the
     *            domains under a domain (*.example.com), or the domains starting with a label
     *            (mail.*). Case and a trailing dot do not matter.
     * @param rawSpfRecord
     *            the spfRecord to add
     * @throws IllegalArgumentException
     *             get thrown on invalid spfRecord
     */
    public void addEntry(String rawHost, String rawSpfRecord)
            throws IllegalArgumentException {
        try {
            LOGGER.debug("Start parsing SPF-Record: {}", rawSpfRecord);
            SPF1Record spfRecord = parser.parse(rawSpfRecord);
            String host = normalize(rawHost);
            LOGGER.debug("Convert host {} to {}", rawHost, host);

            entryMap.put(host, spfRecord);
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
        LOGGER.debug("Clear all entries");
        entryMap.clear();
    }

    /**
     * Remove entry
     * 
     * @param host
     *            The host, as given to {@link #addEntry(String, String)}
     */
    public void removeEntry(String host) {
        LOGGER.debug("Remove fallback entry for host: {}", host);
        entryMap.remove(normalize(host));
    }

    /**
     * @see org.apache.james.jspf.policies.PolicyPostFilter#getSPFRecord(java.lang.String, org.apache.james.jspf.core.SPF1Record)
     */
    public SPF1Record getSPFRecord(String currentDomain, SPF1Record res) throws PermErrorException, TempErrorException, NoneException, NeutralException {
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
        SPF1Record entry = null;

        synchronized (entryMap) {
            entry = getRawEntry(host);
        }

        if (entry != null) {
            return copyOf(entry);
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
     * @return the stored object for the given host or null: the entry of the host
     *         itself, else the one of the longest pattern matching it (of patterns of the same
     *         length, the last in alphabetical order, whatever the order they were added in)
     */
    private SPF1Record getRawEntry(String host) {
        String name = normalize(host);
        SPF1Record entry = entryMap.get(name);
        if (entry != null) {
            return entry;
        }
        return entryMap.entrySet().stream()
            .filter(candidate -> matches(candidate.getKey(), name))
            .max(Comparator.comparingInt((Map.Entry<String, SPF1Record> candidate) -> candidate.getKey().length())
                .thenComparing(Map.Entry::getKey))
            .map(Map.Entry::getValue)
            .orElse(null);
    }

}
