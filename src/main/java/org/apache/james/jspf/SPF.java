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

import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.FutureSPFResult;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.MacroExpand;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPF1Utils;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerExceptionCatcher;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.core.SPFResult;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.dns.DNSService;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.SPFErrorConstants;
import org.apache.james.jspf.exceptions.SPFResultException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.executor.SPFExecutor;
import org.apache.james.jspf.executor.SynchronousSPFExecutor;
import org.apache.james.jspf.parser.RFC4408SPF1Parser;
import org.apache.james.jspf.parser.DefaultTermsFactory;
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
import org.apache.james.jspf.wiring.DNSServiceEnabled;
import org.apache.james.jspf.wiring.LogEnabled;
import org.apache.james.jspf.wiring.MacroExpandEnabled;
import org.apache.james.jspf.wiring.SPFCheckEnabled;
import org.apache.james.jspf.wiring.WiringServiceTable;

import java.util.Iterator;
import java.util.LinkedList;

/**
 * This class is used to generate a SPF-Test and provided all intressting data.
 */
public class SPF implements SPFChecker {

    private final class SPFCheckerExceptionCatcherImplementation implements
            SPFCheckerExceptionCatcher {
        private SPFChecker resultHandler;

        public SPFCheckerExceptionCatcherImplementation(SPFChecker resultHandler) {
            this.resultHandler = resultHandler;
        }

        /**
         * @see org.apache.james.jspf.core.SPFCheckerExceptionCatcher#onException(java.lang.Exception, org.apache.james.jspf.core.SPFSession)
         */
        public void onException(Exception exception, SPFSession session)
                throws PermErrorException, NoneException, TempErrorException,
                NeutralException {

            SPFChecker checker;
            while ((checker = session.popChecker())!=resultHandler) {
                log.debug("Redirect resulted in exception. Removing checker: "+checker);
            }

            String result;
            if (exception instanceof SPFResultException) {
                result = ((SPFResultException) exception).getResult();
                if (!SPFErrorConstants.NEUTRAL_CONV.equals(result)) {
                    log.warn(exception.getMessage(),exception);
                }
            } else {
                // this should never happen at all. But anyway we will set the
                // result to neutral. Safety first ..
                log.error(exception.getMessage(),exception);
                result = SPF1Constants.NEUTRAL;
            }
            session.setCurrentResultExpanded(result);
            
        }
    }

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
            
            LinkedList policyCheckers = new LinkedList();
            
            Iterator i = spfRecord.iterator();
            while (i.hasNext()) {
                SPFChecker checker = (SPFChecker) i.next();
                policyCheckers.add(checker);
            }

            while (policyCheckers.size() > 0) {
                SPFChecker removeLast = (SPFChecker) policyCheckers.removeLast();
                spfData.pushChecker(removeLast);
            }

            return null;
        }
    }

    private static final class PolicyChecker implements SPFChecker {
        
        private LinkedList policies;
        
        public PolicyChecker(LinkedList policies) {
            this.policies = policies;
        }
        
        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException, TempErrorException,
                NeutralException, NoneException {
            
            while (policies.size() > 0) {
                SPFChecker removeLast = (SPFChecker) policies.removeLast();
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

    private Logger log;
    
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
        this.parser = new RFC4408SPF1Parser(logger.getChildLogger("parser"), new DefaultTermsFactory(logger.getChildLogger("termsfactory"), wiringService));
        // We add this after the parser creation because services cannot be null
        wiringService.put(SPFCheckEnabled.class, this);
        this.executor = new SynchronousSPFExecutor(log, dnsProbe);
    }
    
    
    /**
     * Uses passed services
     * 
     * @param dnsProbe the dns provider
     * @param parser the parser to use
     * @param logger the logger to use
     */
    public SPF(DNSService dnsProbe, SPFRecordParser parser, Logger logger, MacroExpand macroExpand, SPFExecutor executor) {
        super();
        this.dnsProbe = dnsProbe;
        this.parser = parser;
        this.log = logger;
        this.macroExpand = macroExpand;
        this.executor = executor;
    }

    
    private static final class DefaultSPFChecker implements SPFChecker {

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
        try {
            spfData = new SPFSession(mailFrom, hostName, ipAddress);
        } catch (PermErrorException e1) {
            spfData.setCurrentResultExpanded(e1.getResult());
        } catch (NoneException e1) {
            spfData.setCurrentResultExpanded(e1.getResult());
        }

        SPFChecker resultHandler = new DefaultSPFChecker();
        
        spfData.pushChecker(resultHandler);
        spfData.pushChecker(this);
        spfData.pushExceptionCatcher(new SPFCheckerExceptionCatcherImplementation(resultHandler));
        
        FutureSPFResult ret = new FutureSPFResult();
        
        executor.execute(spfData, ret);

        // if we call ret.getResult it waits the result ;-)
//        log.info("[ipAddress=" + ipAddress + "] [mailFrom=" + mailFrom
//                + "] [helo=" + hostName + "] => " + ret.getResult());

        return ret;

    }


    /**
     * @see org.apache.james.jspf.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
     */
    public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException,
            NoneException, TempErrorException, NeutralException {

        SPFChecker policyChecker = new PolicyChecker(getPolicies());
        SPFChecker recordChecker = new SPFRecordChecker();
        
        spfData.pushChecker(recordChecker);
        spfData.pushChecker(policyChecker);
        
        return null;
    }

    /**
     * Return a default policy for SPF
     */
    public LinkedList getPolicies() {

        LinkedList policies = new LinkedList();
        
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
            policies.add(new SPFPolicyPostFilterChecker(new TrustedForwarderPolicy(log)));
        }

        policies.add(new SPFPolicyPostFilterChecker(new NeutralIfNotMatchPolicy()));

        policies.add(new SPFPolicyPostFilterChecker(new DefaultExplanationPolicy(log, defaultExplanation, macroExpand)));
        
        return policies;
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
