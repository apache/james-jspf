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

package org.apache.james.jspf.parser;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;

/**
 * Keeps the records parsed by a parser, keyed by their text, so that every check does not parse
 * again the records it retrieves: a provider include tree, the same for most of the mail a server
 * receives, is parsed once.
 *
 * The terms of a cached record are shared by the checks: the terms of jSPF keep only their
 * configuration, the state of a check lives in its SPFSession. Each call returns a new SPF1Record
 * holding these terms, as the policies add modifiers to the record they get.
 *
 * The records are the sender's: the cache keeps at most a given number of them, the least
 * recently used ones being dropped, and not the longer ones, the ones with more terms than a
 * legitimate record has nor the invalid ones: a short text can hold many terms, each one kept as
 * several objects.
 */
public class CachingSPFRecordParser implements SPFRecordParser {

    /**
     * The number of records kept by default
     */
    public static final int DEFAULT_MAX_RECORDS = 1000;

    /**
     * The length of the longest record kept by default: more than most of the legitimate records,
     * which are made to fit in a DNS answer over UDP
     */
    public static final int DEFAULT_MAX_RECORD_LENGTH = 2048;

    /**
     * The number of terms, directives and modifiers, of the largest record kept by default: more
     * than the legitimate records have, the evaluation of a record being limited to 10 lookups
     */
    public static final int DEFAULT_MAX_RECORD_TERMS = 64;

    private final SPFRecordParser parser;

    private final int maxRecordLength;

    private final int maxRecordTerms;

    private final Map<String, SPF1Record> records;

    /**
     * @param parser the parser of the records not cached
     */
    public CachingSPFRecordParser(SPFRecordParser parser) {
        this(parser, DEFAULT_MAX_RECORDS, DEFAULT_MAX_RECORD_LENGTH);
    }

    /**
     * @param parser the parser of the records not cached
     * @param maxRecords the number of records kept at most
     * @param maxRecordLength the length of the longest record kept
     */
    public CachingSPFRecordParser(SPFRecordParser parser, final int maxRecords, int maxRecordLength) {
        this(parser, maxRecords, maxRecordLength, DEFAULT_MAX_RECORD_TERMS);
    }

    /**
     * @param parser the parser of the records not cached
     * @param maxRecords the number of records kept at most
     * @param maxRecordLength the length of the longest record kept
     * @param maxRecordTerms the number of terms of the largest record kept
     */
    public CachingSPFRecordParser(SPFRecordParser parser, final int maxRecords, int maxRecordLength, int maxRecordTerms) {
        this.parser = parser;
        this.maxRecordLength = maxRecordLength;
        this.maxRecordTerms = maxRecordTerms;
        this.records = new LinkedHashMap<String, SPF1Record>(16, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, SPF1Record> eldest) {
                return size() > maxRecords;
            }
        };
    }

    /**
     * @see org.apache.james.jspf.core.SPFRecordParser#parse(java.lang.String)
     */
    public SPF1Record parse(String spfRecord) throws PermErrorException, NoneException, NeutralException {
        if (spfRecord == null || spfRecord.length() > maxRecordLength) {
            return parser.parse(spfRecord);
        }
        SPF1Record parsed;
        synchronized (records) {
            parsed = records.get(spfRecord);
        }
        if (parsed == null) {
            // an invalid record throws: it is not kept
            parsed = parser.parse(spfRecord);
            if (parsed.getDirectives().size() + parsed.getModifiers().size() > maxRecordTerms) {
                // a record with that many terms is not a legitimate one: it is not kept
                return parsed;
            }
            synchronized (records) {
                records.put(spfRecord, parsed);
            }
        }
        return copy(parsed);
    }

    /**
     * @return the number of records kept
     */
    public int size() {
        synchronized (records) {
            return records.size();
        }
    }

    private static SPF1Record copy(SPF1Record parsed) {
        SPF1Record copy = new SPF1Record(parsed.getRecord());
        copy.getDirectives().addAll(parsed.getDirectives());
        copy.getModifiers().addAll(parsed.getModifiers());
        return copy;
    }
}
