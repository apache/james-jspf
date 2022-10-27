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

import java.util.Iterator;
import java.util.LinkedList;
import java.util.concurrent.CompletableFuture;

import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.DNSServiceEnabled;
import org.apache.james.jspf.core.MacroExpand;
import org.apache.james.jspf.core.MacroExpandEnabled;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPF1Utils;
import org.apache.james.jspf.core.SPFCheckEnabled;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerExceptionCatcher;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.apache.james.jspf.core.exceptions.SPFResultException;
import org.apache.james.jspf.core.exceptions.TempErrorException;
import org.apache.james.jspf.executor.AsynchronousSPFExecutor;
import org.apache.james.jspf.executor.FutureSPFResult;
import org.apache.james.jspf.executor.SPFExecutor;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.executor.SynchronousSPFExecutor;
import org.apache.james.jspf.parser.RFC4408SPF1Parser;
import org.apache.james.jspf.policies.InitialChecksPolicy;
import org.apache.james.jspf.policies.NeutralIfNotMatchPolicy;
import org.apache.james.jspf.policies.NoSPFRecordFoundPolicy;
import org.apache.james.jspf.policies.ParseRecordPolicy;
import org.apache.james.jspf.policies.Policy;
import org.apache.james.jspf.policies.PolicyPostFilter;
import org.apache.james.jspf.policies.SPFRetriever;
import org.apache.james.jspf.policies.SPFStrictCheckerRetriever;
import org.apache.james.jspf.policies.local.BestGuessPolicy;
import org.apache.james.jspf.policies.local.DefaultExplanationPolicy;
import org.apache.james.jspf.policies.local.FallbackPolicy;
import org.apache.james.jspf.policies.local.OverridePolicy;
import org.apache.james.jspf.policies.local.TrustedForwarderPolicy;
import org.apache.james.jspf.wiring.WiringServiceTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to generate a SPF-Test and provided all intressting data.
 */
public class SPF implements SPFChecker {
    private static final Logger LOGGER = LoggerFactory.getLogger(SPF.class);

    private static final class SPFRecordChecker implements SPFChecker {
        
        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException, TempErrorException,
                NeutralException, NoneException {
            
            SPF1Record spfRecord = (SPF1Record) spfData.getAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD);
            // make sure we cleanup the record, for recursion support
            spfData.removeAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD);
            
            LinkedList<SPFChecker> policyCheckers = new LinkedList<SPFChecker>();
            
            Iterator<SPFChecker> i = spfRecord.iterator();
            while (i.hasNext()) {
                SPFChecker checker = i.next();
                policyCheckers.add(checker);
            }

            while (policyCheckers.size() > 0) {
                SPFChecker removeLast = policyCheckers.removeLast();
                spfData.pushChecker(removeLast);
            }

            return null;
        }
    }

    private static final class PolicyChecker implements SPFChecker {
        
        private LinkedList<SPFChecker> policies;
        
        public PolicyChecker(LinkedList<SPFChecker> policies) {
            this.policies = policies;
        }
        
        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException, TempErrorException,
                NeutralException, NoneException {
            
            while (policies.size() > 0) {
                SPFChecker removeLast = policies.removeLast();
                spfData.pushChecker(removeLast);
            }
            
            return null;
        }
    }

    private static final class SPFPolicyChecker implements SPFChecker {
        private Policy policy;

        /**
         * @param policy
         */
        public SPFPolicyChecker(Policy policy) {
            this.policy = policy;
        }

        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException, TempErrorException,
                NeutralException, NoneException {
            SPF1Record res = (SPF1Record) spfData.getAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD);
            if (res == null) {
                res = policy.getSPFRecord(spfData.getCurrentDomain());
                spfData.setAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD, res);
            }
            return null;
        }
        
        public String toString() {
            return "PC:"+policy.toString();
        }
    }

    private static final class SPFPolicyPostFilterChecker implements SPFChecker {
        private PolicyPostFilter policy;

        /**
         * @param policy
         */
        public SPFPolicyPostFilterChecker(PolicyPostFilter policy) {
            this.policy = policy;
        }

        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException, TempErrorException,
                NeutralException, NoneException {
            SPF1Record res = (SPF1Record) spfData.getAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD);
            res = policy.getSPFRecord(spfData.getCurrentDomain(), res);
            spfData.setAttribute(SPF1Utils.ATTRIBUTE_SPF1_RECORD, res);
            return null;
        }
        
        public String toString() {
            return "PFC:"+policy.toString();
        }

    }

    private DNSService dnsProbe;

    private SPFRecordParser parser;
    
    private String defaultExplanation = null;
    
    private boolean useBestGuess = false;

    private FallbackPolicy fallBack;
    
    private OverridePolicy override;
    
    private boolean useTrustedForwarder = false;
    
    private boolean mustEquals = false;

    private MacroExpand macroExpand;

    private SPFExecutor executor;

    /**
     * Uses passed logger and passed dnsServicer
     * 
     * @param dnsProbe the dns provider
     */
    public SPF(DNSService dnsProbe) {
        super();
        this.dnsProbe = dnsProbe;
        WiringServiceTable wiringService = new WiringServiceTable();
        wiringService.put(DNSServiceEnabled.class, this.dnsProbe);
        this.macroExpand = new MacroExpand(this.dnsProbe);
        wiringService.put(MacroExpandEnabled.class, this.macroExpand);
        this.parser = new RFC4408SPF1Parser(new DefaultTermsFactory(wiringService));
        // We add this after the parser creation because services cannot be null
        wiringService.put(SPFCheckEnabled.class, this);
        this.executor = new AsynchronousSPFExecutor(dnsProbe);
    }
    
    
    /**
     * Uses passed services
     * 
     * @param dnsProbe the dns provider
     * @param parser the parser to use
     */
    public SPF(DNSService dnsProbe, SPFRecordParser parser, MacroExpand macroExpand, SPFExecutor executor) {
        super();
        this.dnsProbe = dnsProbe;
        this.parser = parser;
        this.macroExpand = macroExpand;
        this.executor = executor;
    }

    
    private static final class DefaultSPFChecker implements SPFChecker, SPFCheckerExceptionCatcher {

        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException, TempErrorException,
                NeutralException, NoneException {
            if (spfData.getCurrentResultExpanded() == null) {
                String resultChar = spfData.getCurrentResult() != null ? spfData.getCurrentResult() : "";
                String result = SPF1Utils.resultToName(resultChar);
                spfData.setCurrentResultExpanded(result);
            }
            return null;
        }
        

        /**
         * @see org.apache.james.jspf.core.SPFCheckerExceptionCatcher#onException(java.lang.Exception, org.apache.james.jspf.core.SPFSession)
         */
        public void onException(Exception exception, SPFSession session)
                throws PermErrorException, NoneException, TempErrorException,
                NeutralException {

            String result;
            if (exception instanceof SPFResultException) {
                result = ((SPFResultException) exception).getResult();
                if (!SPFErrorConstants.NEUTRAL_CONV.equals(result)) {
                    LOGGER.warn(exception.getMessage(),exception);
                }
            } else {
                // this should never happen at all. But anyway we will set the
                // result to neutral. Safety first ..
                LOGGER.error(exception.getMessage(),exception);
                result = SPFErrorConstants.NEUTRAL_CONV;
            }
            session.setCurrentResultExpanded(result);
        }

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

        // Setup the data
        spfData = new SPFSession(mailFrom, hostName, ipAddress);
      

        SPFChecker resultHandler = new DefaultSPFChecker();
        
        spfData.pushChecker(resultHandler);
        spfData.pushChecker(this);
        
        FutureSPFResult ret = new FutureSPFResult();
        
        executor.execute(spfData, ret);

        // if we call ret.getResult it waits the result ;-)
//        log.info("[ipAddress=" + ipAddress + "] [mailFrom=" + mailFrom
//                + "] [helo=" + hostName + "] => " + ret.getResult());

        return ret;

    }


    /**
     * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
            NoneException, TempErrorException, NeutralException {

        // if we already have a result we don't need to add further processing.
        if (spfData.getCurrentResultExpanded() == null && spfData.getCurrentResult() == null) {
            SPFChecker policyChecker = new PolicyChecker(getPolicies());
            SPFChecker recordChecker = new SPFRecordChecker();
            
            spfData.pushChecker(recordChecker);
            spfData.pushChecker(policyChecker);
        }
        
        return null;
    }

    /**
     * Return a default policy for SPF
     */
    public LinkedList<SPFChecker> getPolicies() {

        LinkedList<SPFChecker> policies = new LinkedList<SPFChecker>();
        
        if (override != null) {
            policies.add(new SPFPolicyChecker(override));
        }

        policies.add(new InitialChecksPolicy());

        if (mustEquals) {
            policies.add(new SPFStrictCheckerRetriever());
        } else {
            policies.add(new SPFRetriever());
        }

        if (useBestGuess) {
            policies.add(new SPFPolicyPostFilterChecker(new BestGuessPolicy()));
        }
        
        policies.add(new SPFPolicyPostFilterChecker(new ParseRecordPolicy(parser)));
        
        if (fallBack != null) {
            policies.add(new SPFPolicyPostFilterChecker(fallBack));
        }

        policies.add(new SPFPolicyPostFilterChecker(new NoSPFRecordFoundPolicy()));
        
        // trustedForwarder support is enabled
        if (useTrustedForwarder) {
            policies.add(new SPFPolicyPostFilterChecker(new TrustedForwarderPolicy()));
        }

        policies.add(new SPFPolicyPostFilterChecker(new NeutralIfNotMatchPolicy()));

        policies.add(new SPFPolicyPostFilterChecker(new DefaultExplanationPolicy(defaultExplanation, macroExpand)));
        
        return policies;
    }
    
    /**
     * Set the amount of time (in seconds) before an TermError is returned when
     * the dnsserver not answer. Default is 20 seconds.
     * 
     * @param timeOut The timout in seconds
     */
    public synchronized void setTimeOut(int timeOut) {
        LOGGER.debug("TimeOut was set to: {}", timeOut);
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
            this.fallBack =  new FallbackPolicy(parser);
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
            override = new OverridePolicy(parser);
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
