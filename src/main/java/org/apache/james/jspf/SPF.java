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
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPFCheckerExceptionCatcher;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.SPFResultException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;
import org.apache.james.jspf.parser.DefaultSPF1Parser;
import org.apache.james.jspf.parser.DefaultTermsFactory;
import org.apache.james.jspf.policies.ChainPolicy;
import org.apache.james.jspf.policies.InitialChecksPolicy;
import org.apache.james.jspf.policies.NeutralIfNotMatchPolicy;
import org.apache.james.jspf.policies.NoSPFRecordFoundPolicy;
import org.apache.james.jspf.policies.Policy;
import org.apache.james.jspf.policies.ParseRecordPolicy;
import org.apache.james.jspf.policies.SPFRetriever;
import org.apache.james.jspf.policies.SPFStrictCheckerRetriever;
import org.apache.james.jspf.policies.local.BestGuessPolicy;
import org.apache.james.jspf.policies.local.DefaultExplanationPolicy;
import org.apache.james.jspf.policies.local.FallbackPolicy;
import org.apache.james.jspf.policies.local.OverridePolicy;
import org.apache.james.jspf.policies.local.TrustedForwarderPolicy;
import org.apache.james.jspf.wiring.DNSServiceEnabled;
import org.apache.james.jspf.wiring.LogEnabled;
import org.apache.james.jspf.wiring.MacroExpandEnabled;
import org.apache.james.jspf.wiring.SPFCheckEnabled;
import org.apache.james.jspf.wiring.WiringServiceTable;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;

/**
 * This class is used to generate a SPF-Test and provided all intressting data.
 */
public class SPF implements SPFChecker {

    DNSService dnsProbe;

    public SPFRecordParser parser;

    Logger log;
    
    String defaultExplanation = null;
    
    public boolean useBestGuess = false;

    private FallbackPolicy fallBack;
    
    private OverridePolicy override;
    
    private boolean useTrustedForwarder = false;
    
    private boolean mustEquals = false;

    private MacroExpand macroExpand;

    /**
     * Uses passed logger and passed dnsServicer
     * 
     * @param dnsProbe the dns provider
     * @param logger the logger to use
     */
    public SPF(DNSService dnsProbe, Logger logger) {
        super();
        this.dnsProbe = dnsProbe;
        this.log = logger;
        WiringServiceTable wiringService = new WiringServiceTable();
        wiringService.put(LogEnabled.class, this.log);
        wiringService.put(DNSServiceEnabled.class, this.dnsProbe);
        this.macroExpand = new MacroExpand(logger.getChildLogger("macroExpand"), this.dnsProbe);
        wiringService.put(MacroExpandEnabled.class, this.macroExpand);
        this.parser = new DefaultSPF1Parser(logger.getChildLogger("parser"), new DefaultTermsFactory(logger.getChildLogger("termsfactory"), wiringService));
        // We add this after the parser creation because services cannot be null
        wiringService.put(SPFCheckEnabled.class, this);
    }
    
    
    /**
     * Uses passed services
     * 
     * @param dnsProbe the dns provider
     * @param parser the parser to use
     * @param logger the logger to use
     */
    public SPF(DNSService dnsProbe, SPFRecordParser parser, Logger logger, MacroExpand macroExpand) {
        super();
        this.dnsProbe = dnsProbe;
        this.parser = parser;
        this.log = logger;
        this.macroExpand = macroExpand;
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
        SPFSession spfData = null;
        String result = null;
        String explanation = null;

        try {
            // Setup the data
            spfData = new SPFSession(mailFrom, hostName, ipAddress);
            checkSPF(spfData);
            String resultChar = spfData.getCurrentResult() != null ? spfData.getCurrentResult() : "";
            result = SPF1Utils.resultToName(resultChar);
            explanation = spfData.getExplanation();
        } catch (SPFResultException e) {
            result = e.getResult();
            if (!SPF1Utils.NEUTRAL_CONV.equals(result)) {
                log.warn(e.getMessage(),e);
            }
        } catch (IllegalStateException e) {
            // this should never happen at all. But anyway we will set the
            // result to neutral. Safety first ..
            log.error(e.getMessage(),e);
            result = SPF1Constants.NEUTRAL;
        }

        SPFResult ret = new SPFResult(result, explanation, spfData);
        
        log.info("[ipAddress=" + ipAddress + "] [mailFrom=" + mailFrom
                + "] [helo=" + hostName + "] => " + ret.getResult());

        return ret;

    }
    
    /**
     * @see org.apache.james.jspf.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public void checkSPF(SPFSession spfData) throws PermErrorException,
            NoneException, TempErrorException, NeutralException {

        SPF1Record spfRecord = getPolicy().getSPFRecord(spfData.getCurrentDomain());
        checkSPF(spfData, spfRecord);
    }

    /**
     * Check a given spfData with the given spfRecord
     * 
     * @param spfData spf data
     * @param spfRecord record
     * @throws PermErrorException exception
     * @throws NoneException exception
     * @throws TempErrorException exception
     * @throws NeutralException exception
     */
    public void checkSPF(SPFSession spfData, SPF1Record spfRecord) throws PermErrorException, NoneException, TempErrorException, NeutralException {
        LinkedList reversedCheckers = new LinkedList();
        Iterator i = spfRecord.iterator();
        while (i.hasNext()) {
            reversedCheckers.addFirst(i.next());
        }

        for (int k = 0; k < reversedCheckers.size(); k++) {
            spfData.pushChecker((SPFChecker) reversedCheckers.get(k));
        }
        
        // To make it asynchronous we should start the executor and 
        // return here.. instead we run the executor locally by now.

        SPFChecker checker;
        while ((checker = spfData.popChecker()) != null) {
            // only execute checkers we added (better recursivity)
            log.debug("Executing checker: "+checker);
            try {
                checker.checkSPF(spfData);
            } catch (Exception e) {
                SPFCheckerExceptionCatcher catcher = spfData.getExceptionCatcher();
                if (catcher != null) {
                    catcher.onException(e, spfData);
                } else {
                    log.debug("Checker execution resulted in unmanaged exception: "+checker+" => "+e);
                    if (e instanceof PermErrorException) {
                        throw (PermErrorException) e;
                    } else if (e instanceof TempErrorException) {
                        throw (TempErrorException) e;
                    } else if (e instanceof NeutralException) {
                        throw (NeutralException) e;
                    } else if (e instanceof NoneException) {
                        throw (NeutralException) e;
                    } else {
                        throw new IllegalStateException(e);
                    }
                }
            }
        }
    }

    /**
     * Return a default policy for SPF
     */
    public Policy getPolicy() {

        ArrayList policies = new ArrayList();
        ArrayList policyFilters = new ArrayList();
        
        if (override != null) {
            policies.add(override);
        }
        
        if (mustEquals) {
            policies.add(new SPFStrictCheckerRetriever(dnsProbe));
        } else {
            policies.add(new SPFRetriever(dnsProbe));
        }
        
        if (useBestGuess) {
            policyFilters.add(new BestGuessPolicy());
        }
        
        policyFilters.add(new ParseRecordPolicy(parser));
        
        if (fallBack != null) {
            policyFilters.add(fallBack);
        }

        policyFilters.add(new NoSPFRecordFoundPolicy());
        
        // trustedForwarder support is enabled
        if (useTrustedForwarder) {
            policyFilters.add(new TrustedForwarderPolicy(log));
        }

        policyFilters.add(new NeutralIfNotMatchPolicy());

        policyFilters.add(new DefaultExplanationPolicy(log, defaultExplanation, macroExpand, dnsProbe));
        
        policies.add(new InitialChecksPolicy());
        
        return new ChainPolicy(policies, policyFilters);
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
     * Return the FallbackPolicy object which can be used to 
     * provide default spfRecords for hosts which have no records
     * 
     * @return the FallbackPolicy object
     */
    public synchronized FallbackPolicy getFallbackPolicy() {
        // Initialize fallback policy
        if (fallBack == null) {
            this.fallBack =  new FallbackPolicy(log.getChildLogger("fallbackpolicy"), parser);
        }
        return fallBack;
    }
    
    /**
     * Set to true to enable trusted-forwarder.org whitelist. The whitelist will only be queried if
     * the last Mechanism is -all or ?all. 
     * See http://trusted-forwarder.org for more informations
     * Default is false.
     * 
     * @param useTrustedForwarder true or false
     */
    public synchronized void setUseTrustedForwarder(boolean useTrustedForwarder) {
        this.useTrustedForwarder = useTrustedForwarder;
    }
    
    /**
     * Return the OverridePolicy object which can be used to
     * override spfRecords for hosts
     * 
     * @return the OverridePolicy object
     */
    public synchronized OverridePolicy getOverridePolicy() {
        if (override == null) {
            override = new OverridePolicy(log.getChildLogger("overridepolicy"), parser);
        }
        return override;
    }
    
    /**
     * Set to true if a PermError should returned when a domain publish a SPF-Type
     * and TXT-Type SPF-Record and both are not equals. Defaults false
     * 
     * @param mustEquals true or false
     */
    public synchronized void setSPFMustEqualsTXT(boolean mustEquals) {
        this.mustEquals = mustEquals;
    }
}
