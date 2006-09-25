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


package org.apache.james.jspf;

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.Directive;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.Modifier;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Data;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.parser.SPF1Parser;

import java.util.Iterator;
import java.util.List;

/**
 * This class is used to generate a SPF-Test and provided all intressting data.
 * 
 */

public class SPF {

    private DNSService dnsProbe;

    private SPF1Parser parser;

    private Logger log;
    
    private String defaultExplanation = null;

    private boolean useBestGuess = false;
    
    /**
     * Uses default Log4JLogger and DNSJava based dns resolver
     */
    public SPF() {
        this(new Log4JLogger(org.apache.log4j.Logger.getLogger(SPF.class)));
    }
    
    /**
     * Uses passed logger and DNSJava based dns resolver
     * 
     * @param logger the logger to use
     */
    public SPF(Logger logger) {
        this(new DNSServiceXBillImpl(logger), logger);
    }

    /**
     * Uses passed logger and passed dnsServicer
     * 
     * @param dnsProbe the dns provider
     * @param logger the logger to use
     */
    public SPF(DNSService dnsProbe, Logger logger) {
        super();
        this.dnsProbe = dnsProbe;
        this.parser = new SPF1Parser(logger);
        this.log = logger;
    }

    /**
     * Run check for SPF with the given values.
     * 
     * @param ipAddress
     *            The ipAddress the connection is comming from
     * @param mailFrom
     *            The mailFrom which was provided
     * @param hostName
     *            The hostname which was provided as HELO/EHLO
     * @return result The SPFResult
     */
    public SPFResult checkSPF(String ipAddress, String mailFrom, String hostName) {
        SPF1Data spfData = null;
        String result = null;
        String resultChar = null;
        String explanation = null;

        try {
            // Setup the data
            spfData = new SPF1Data(mailFrom, hostName, ipAddress, dnsProbe);
            SPFInternalResult res = checkSPF(spfData);
            resultChar = res.getResultChar();
            result = SPF1Utils.resultToName(resultChar);
            explanation = res.getExplanation();
        } catch (PermErrorException e) {
            log.warn(e.getMessage(),e);
            result = SPF1Utils.PERM_ERROR_CONV;
        } catch (NoneException e) {
            log.warn(e.getMessage(),e);
            result = SPF1Utils.NONE_CONV;
        } catch (NeutralException e) {
            result = SPF1Utils.NEUTRAL_CONV;
        } catch (TempErrorException e) {
            log.warn(e.getMessage(),e);
            result = SPF1Utils.TEMP_ERROR_CONV;
        } catch (IllegalStateException e) {
            // this should never happen at all. But anyway we will set the
            // result to neutral. Safety first ..
            log.error(e.getMessage(),e);
            result = SPF1Constants.NEUTRAL;
        }

        SPFResult ret = new SPFResult(result, resultChar, explanation, spfData);
        
        log.info("[ipAddress=" + ipAddress + "] [mailFrom=" + mailFrom
                + "] [helo=" + hostName + "] => " + ret.getResult());

        return ret;

    }

    /**
     * Run check for SPF with the given values.
     * 
     * @param spfData
     *             The SPF1Data which should be used to run the check
     * @return result 
     *             The SPFInternalResult 
     * @throws PermErrorException
     *             Get thrown if an error was detected
     * @throws NoneException
     *             Get thrown if no Record was found
     * @throws TempErrorException
     *             Get thrown if a DNS problem was detected
     * @throws NeutralException  
     *             Get thrown if the result should be neutral
     */
    public SPFInternalResult checkSPF(SPF1Data spfData) throws PermErrorException,
            NoneException, TempErrorException, NeutralException {
        String result = SPF1Constants.NEUTRAL;
        String explanation = null;
        
        // Initial checks (spec 4.3)
        if (spfData.getCurrentDomain() != null) {
            String[] labels = spfData.getCurrentDomain().split("\\.");
            for (int i = 0; i < labels.length; i++) {
                if (labels[i] != null && labels[i].length() > 63) {
                    throw new NoneException("Domain "+spfData.getCurrentDomain()+" is malformed (label longer than 63 characters)");
                }
            }
        }

        // Get the raw dns txt entry which contains a spf entry
        String spfDnsEntry = getSpfRecord(dnsProbe,spfData.getCurrentDomain(),
                SPF1Constants.SPF_VERSION);

        // No SPF-Record found
        if (spfDnsEntry == null) {
            // We should use bestguess
            if (useBestGuess == true) {
                spfDnsEntry = SPF1Utils.BEST_GUESS_RECORD;
            } else {
                throw new NoneException("No SPF record found for host: " + spfData.getCurrentDomain());
            }
        }

        // logging
        log.debug("Start parsing SPF-Record:" + spfDnsEntry);

        SPF1Record spfRecord = parser.parse(spfDnsEntry);

        String qualifier = null;
        boolean hasCommand = false;

        // get all commands
        Iterator com = spfRecord.getDirectives().iterator();
        while (com.hasNext()) {

            // if we reach maximum calls we must throw a PermErrorException. See
            // SPF-RFC Section 10.1. Processing Limits
            if (spfData.getCurrentDepth() > spfData.getMaxDepth()) {
                throw new PermErrorException(
                        "Maximum mechanism/modifier calls done: "
                                + spfData.getCurrentDepth());
            }

            hasCommand = true;
            Directive d = (Directive) com.next();

            // logging
            log.debug("Processing directive: " + d.getQualifier()
                    + d.getMechanism().toString());

            qualifier = d.run(spfData);

            // logging
            log.debug("Processed directive: " + d.getQualifier()
                    + d.getMechanism().toString() + " returned " + qualifier);

            if (qualifier != null) {
                if (qualifier.equals("")) {
                    result = SPF1Constants.PASS;
                } else {
                    result = qualifier;
                }

                spfData.setCurrentResult(result);
                spfData.setMatch(true);

                // If we have a match we should break the while loop
                break;
            }
        }

        Iterator mod = spfRecord.getModifiers().iterator();
        while (mod.hasNext()) {
            spfData.setCurrentDepth(spfData.getCurrentDepth() + 1);

            // if we reach maximum calls we must throw a PermErrorException. See
            // SPF-RFC Section 10.1. Processing Limits
            if (spfData.getCurrentDepth() > spfData.getMaxDepth()) {
                throw new PermErrorException(
                        "Maximum mechanism/modifiers calls done: "
                                + spfData.getCurrentDepth());
            }

            Modifier m = (Modifier) mod.next();

            log.debug("Processing modifier: " + m.toString());

            String q = m.run(spfData);

            log.debug("Processed modifier: " + m.toString() + " resulted in "
                    + q);

            if (q != null) {
                qualifier = q;
            }

            if (qualifier != null) {
                result = qualifier;

                spfData.setCurrentResult(result);
                spfData.setMatch(true);
            }
        }

        // If no match was found set the result to neutral
        if (!spfData.isMatch() && (hasCommand == true)) {
            result = SPF1Constants.NEUTRAL;
        } 
        
        if (result.equals(SPF1Constants.FAIL)) {  
            if (spfData.getExplanation()==null || spfData.getExplanation().equals("")) {
                if(defaultExplanation == null) {
                    try {
                        spfData.setExplanation(new MacroExpand(spfData, log)
                                .expandExplanation(SPF1Utils.DEFAULT_EXPLANATION));
                    } catch (PermErrorException e) {
                        // Should never happen !
                        log.debug("Invalid defaulfExplanation: " + SPF1Utils.DEFAULT_EXPLANATION);
                    }
                } else {
                    try {
                        spfData.setExplanation(new MacroExpand(spfData, log)
                                .expandExplanation(defaultExplanation));
                    } catch (PermErrorException e) {
                        log.error("Invalid defaultExplanation: " + defaultExplanation);
                    }
                }
            }
            explanation = spfData.getExplanation();
        }
        
        return new SPFInternalResult(result, explanation);
    }

    /**
     * Set the amount of time (in seconds) before an TermError is returned when
     * the dnsserver not answer. Default is 20 seconds.
     * 
     * @param timeOut The timout in seconds
     */
    public synchronized void setTimeOut(int timeOut) {
        log.debug("TimeOut was set to: " + timeOut);
        dnsProbe.setTimeOut(timeOut);
    }
    
    /**
     * Set the default explanation which will be used if no explanation is found in the SPF Record
     *  
     * @param defaultExplanation The explanation to use if no explanation is found in the SPF Record
     */
    public synchronized void setDefaultExplanation(String defaultExplanation) {
        this.defaultExplanation = defaultExplanation;      
    }
    
    /**
     * Set to true for using best guess. Best guess will set the SPF-Record to "a/24 mx/24 ptr ~all" 
     * if no SPF-Record was found for the doamin. When this was happen only pass or netural will be returned.
     * Default is false.
     * 
     * @param useBestGuess true to enable best guess
     */
    public synchronized void setUseBestGuess(boolean useBestGuess) {
        this.useBestGuess  = useBestGuess;
    }
    

    /**
     * Get the SPF-Record for a server given it's version
     * 
     * TODO: support SPF Records too. This will be done if dnsjava support it!
     * 
     * @param dns
     *            The dns service to query
     * @param hostname
     *            The hostname for which we want to retrieve the SPF-Record
     * @param spfVersion
     *            The SPF-Version which should used.
     * @return The SPF-Record if one is found.
     * @throws PermErrorException
     *             if more then one SPF-Record was found.
     * @throws TempErrorException
     *             if the lookup result was "TRY_AGAIN"
     */
    public String getSpfRecord(DNSService dns, String hostname, String spfVersion)
            throws PermErrorException, TempErrorException {

        String returnValue = null;
        try {
            List spfR = dns.getRecords(hostname, DNSService.SPF);
            if (spfR == null || spfR.isEmpty()) {
                // do DNS lookup for TXT
                spfR = dns.getRecords(hostname, DNSService.TXT);
            }
    
            // process returned records
            if (spfR != null && !spfR.isEmpty()) {
    
                Iterator all = spfR.iterator();
    
                while (all.hasNext()) {
                    // DO NOT trim the result!
                    String compare = all.next().toString();
    
                    // TODO is this correct? we remove the first and last char if the
                    // result has an initial " 
                    // remove '"'
                    if (compare.charAt(0)=='"') {
                        compare = compare.toLowerCase().substring(1,
                                compare.length() - 1);
                    }
    
                    // We trim the compare value only for the comparison
                    if (compare.trim().startsWith(spfVersion + " ") || compare.trim().equals(spfVersion)) {
                        if (returnValue == null) {
                            returnValue = compare;
                        } else {
                            throw new PermErrorException(
                                    "More than 1 SPF record found for host: " + hostname);
                        }
                    }
                }
            }
            return returnValue;
        } catch (DNSService.TimeoutException e) {
            throw new TempErrorException("Timeout querying dns");
        }
    }

}
