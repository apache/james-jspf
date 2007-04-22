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

package org.apache.james.jspf.util;

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSResponse;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.core.SPFChecker;
import org.apache.james.jspf.core.SPFCheckerDNSResponseListener;
import org.apache.james.jspf.core.SPFSession;
import org.apache.james.jspf.core.DNSService.TimeoutException;
import org.apache.james.jspf.exceptions.NeutralException;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;
import org.apache.james.jspf.macro.MacroExpand;

import java.util.Iterator;
import java.util.List;

public class DNSResolver {
    
    private static final String ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD = "MacroExpand.checkedRecord";

    /**
     * This is used temporarily to synchronously obtain a DNSResponse for a DNSRequest
     */
    public static DNSResponse lookup(DNSService service, DNSRequest request) {
        try {
            return new DNSResponse(service.getRecords(request.getHostname(), request.getRecordType()));
        } catch (TimeoutException e) {
            return new DNSResponse(e);
        }
    }
    
    public static void hostExpand(DNSService dnsService, MacroExpand macroExpand, String input, final SPFSession spfSession, boolean isExplanation, final SPFChecker next) throws PermErrorException, TempErrorException, NeutralException, NoneException {
        if (input != null) {
            String host = macroExpand.expand(input, spfSession, isExplanation);
            if (host == null) {
                new SPFCheckerDNSResponseListener() {
    
                    private DNSService dnsService;
    
                    public void onDNSResponse(DNSResponse response,
                            SPFSession session) throws PermErrorException,
                            NoneException, TempErrorException, NeutralException {
                        
                        try {
                            boolean ip6 = IPAddr.isIPV6(session.getIpAddress());
                            List records = response.getResponse();
        
                            if (records != null && records.size() > 0) {
                                String record = (String) records.get(0);
                                spfSession.setAttribute(ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD, record);
                                
                                DNSResponse resp = DNSResolver.lookup(dnsService, new DNSRequest(record, ip6 ? DNSService.AAAA : DNSService.A));
                                new SPFCheckerDNSResponseListener() {
                                    
                                    public void onDNSResponse(DNSResponse response,
                                            SPFSession session) throws PermErrorException,
                                            NoneException, TempErrorException, NeutralException {
                                        // just return the default "unknown" if we cannot find anything later
                                        spfSession.setClientDomain("unknown");
                                        try {
                                            List records = response.getResponse();
                                            if (records != null && records.size() > 0) {
                                                Iterator i = records.iterator();
                                                while (i.hasNext()) {
                                                    String next = (String) i.next();
                                                    if (IPAddr.getAddress(session.getIpAddress()).toString().equals(IPAddr.getAddress(next).toString())) {
                                                        spfSession.setClientDomain((String) spfSession.getAttribute(ATTRIBUTE_MACRO_EXPAND_CHECKED_RECORD));
                                                        break;
                                                    }
                                                }
                                            }
                                        } catch (TimeoutException e) {
                                            // just return the default "unknown".
                                        } catch (PermErrorException e) {
                                            // just return the default "unknown".
                                        }
                                        
                                        next.checkSPF(spfSession);
    
                                    }
                                }.onDNSResponse(resp, session);
                                
                            }
                        } catch (TimeoutException e) {
                            // just return the default "unknown".
                            spfSession.setClientDomain("unknown");
                            next.checkSPF(spfSession);
                        } catch (PermErrorException e) {
                            // just return the default "unknown".
                            spfSession.setClientDomain("unknown");
                            next.checkSPF(spfSession);
                        }
                        
                    }
    
                    public SPFCheckerDNSResponseListener setDNSService(
                            DNSService dnsService) {
                        this.dnsService = dnsService;
                        return this;
                    }
                    
                }.setDNSService(dnsService).onDNSResponse(DNSResolver.lookup(dnsService, new DNSRequest(IPAddr.getAddress(spfSession.getIpAddress()).getReverseIP(), DNSService.PTR)), spfSession);
            } else {
                next.checkSPF(spfSession);
            }
        } else {
            next.checkSPF(spfSession);
        }
    }

}
