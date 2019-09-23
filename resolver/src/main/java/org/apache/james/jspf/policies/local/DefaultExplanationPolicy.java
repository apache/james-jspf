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

import org.apache.james.jspf.core.DNSLookupContinuation;
import org.apache.james.jspf.core.MacroExpand;
import org.apache.james.jspf.core.SPF1Constants;
import org.apache.james.jspf.core.SPF1Record;
import org.apache.james.jspf.core.SPF1Utils;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.exceptions.NeutralException;
import org.apache.james.jspf.core.exceptions.NoneException;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.core.exceptions.TempErrorException;
import org.apache.james.jspf.executor.FutureSPFResult;
import org.apache.james.jspf.policies.PolicyPostFilter;
import org.apache.james.jspf.terms.Modifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Policy to add a default explanation
 */
public final class DefaultExplanationPolicy implements PolicyPostFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultExplanationPolicy.class);
    
    private final class ExplanationChecker implements SPFChecker {
        
        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData)
                throws PermErrorException,
                NoneException, TempErrorException,
                NeutralException {
            String attExplanation = (String) spfData.getAttribute(ATTRIBUTE_DEFAULT_EXPLANATION_POLICY_EXPLANATION);
            try {
                String explanation = macroExpand.expand(attExplanation, spfData, MacroExpand.EXPLANATION);
                
                spfData.setExplanation(explanation);
            } catch (PermErrorException e) {
                // Should never happen !
                LOGGER.debug("Invalid defaulfExplanation: {}", attExplanation);
            }
            return null;
        }
    }

    private final class DefaultExplanationChecker implements Modifier {
        
        private SPFChecker explanationCheckr = new ExplanationChecker();
        
        /**
         * @see org.apache.james.jspf.core.SPFChecker#checkSPF(org.apache.james.jspf.core.SPFSession)
         */
        public DNSLookupContinuation checkSPF(SPFSession spfData) throws PermErrorException, NoneException, TempErrorException, NeutralException {
            
            if (SPF1Constants.FAIL.equals(spfData.getCurrentResult())) {  
                if (spfData.getExplanation()==null || spfData.getExplanation().equals("")) {
                    String explanation;
                    if (defExplanation == null) {
                        explanation = SPF1Utils.DEFAULT_EXPLANATION;
                    } else {
                        explanation = defExplanation;
                    }
                    spfData.setAttribute(ATTRIBUTE_DEFAULT_EXPLANATION_POLICY_EXPLANATION, explanation);
                    spfData.pushChecker(explanationCheckr);
                    return macroExpand.checkExpand(explanation, spfData, MacroExpand.EXPLANATION);
                }
            }
            
            return null;
        }

        public String toString() {
            if (defExplanation == null) {
                return "defaultExplanation";
            } else {
                return "defaultExplanation="+defExplanation;
            }
        }

        /**
         * (non-Javadoc)
         * @see org.apache.james.jspf.terms.Modifier#enforceSingleInstance()
         */
		public boolean enforceSingleInstance() {
			return false;
		}
    }

    private static final String ATTRIBUTE_DEFAULT_EXPLANATION_POLICY_EXPLANATION = "DefaultExplanationPolicy.explanation";

    /**
     * the default explanation
     */
    private String defExplanation;
    
    private MacroExpand macroExpand;
    
    /**
     * @param explanation the default explanation
     * @param macroExpand the MacroExpand service
     */
    public DefaultExplanationPolicy(String explanation, MacroExpand macroExpand) {
        this.defExplanation = explanation;
        this.macroExpand = macroExpand;
    }

    /**
     * @see org.apache.james.jspf.policies.PolicyPostFilter#getSPFRecord(java.lang.String, org.apache.james.jspf.core.SPF1Record)
     */
    public SPF1Record getSPFRecord(String currentDomain, SPF1Record spfRecord) throws PermErrorException, TempErrorException, NoneException, NeutralException {
        if (spfRecord == null) return null;
        // Default explanation policy.
        spfRecord.getModifiers().add(new DefaultExplanationChecker());
        return spfRecord;
    }
}