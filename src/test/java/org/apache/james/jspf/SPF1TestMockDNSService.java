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
import org.apache.james.jspf.core.IPAddr;
import org.apache.james.jspf.exceptions.NoneException;
import org.apache.james.jspf.exceptions.PermErrorException;
import org.apache.james.jspf.exceptions.TempErrorException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class SPF1TestMockDNSService implements DNSService {
    
    public String getSpfRecord(String hostname, String spfVersion)
            throws PermErrorException, NoneException, TempErrorException {
       
        if ("v=spf1".equals(spfVersion)) {
            if ("spf1-test.foo.bar".equals(hostname))
                return "v=spf1 redirect=spf2-test.foo.bar +all";
            if ("spf2-test.foo.bar".equals(hostname)) 
                return "v=spf1 -all";
            if ("spf3-test.foo.bar".equals(hostname))
                return "v=spf1 redirect=spf2-test.foo.bar";
            
            // include tests
            if ("spf4-test.foo.bar".equals(hostname))
                return "v=spf1 include:spf2-test.foo.bar +all";
            if ("spf5-test.foo.bar".equals(hostname))
                return "v=spf1 include:spf6-test.foo.bar -all";
            if ("spf6-test.foo.bar".equals(hostname))
                throw new NoneException(
                        "No TXTRecord found for: spf6-test.foo.bar");
            if ("spf7-test.foo.bar".equals(hostname)) 
                return "v=spf1 include:spf8-test.foo.bar";
            if ("spf8-test.foo.bar".equals(hostname))
                return "v=spf1 -all";
            if ("spf9-test.foo.bar".equals(hostname))
                return "v=spf1 include:spf10-test.foo.bar +all";
            if ("spf10-test.foo.bar".equals(hostname))
                return "v=spf1 ?all";
            if ("spf11-test.foo.bar".equals(hostname))
                return "v=spf1 include:spf12-test.foo.bar +all";
            if ("spf12-test.foo.bar".equals(hostname))
                return "v=spf1 ~all";
            if ("spf13-test.foo.bar".equals(hostname))
                return "v=spf1 include:spf14-test.foo.bar -all exp=spf17-test.foo.bar";
            if ("spf14-test.foo.bar".equals(hostname))
                return "v=spf1 -all exp=spf14-test.foo.bar";
            if ("spf15-test.foo.bar".equals(hostname))
                return "v=spf1 redirect=spf16-test.foo.bar exp=spf17-test.foo.bar";
            if ("spf16-test.foo.bar".equals(hostname))
                return "v=spf1 -all exp=spf16-test.foo.bar";
            if ("spf18-test.foo.bar".equals(hostname))
                return "v=spf1 +ip6:FEDC:BA98:7654:3210:FEDC:BA98:7654:3210 -all";
            if ("spf19-test.foo.bar".equals(hostname))
                return "v=spf1 +ip6:::1 -all";
            if ("spf20-test.foo.bar".equals(hostname))
                return "v=spf1 +ip6:2001:1234:5678:9ABC::/64 -all"; 
            if ("spf21-test.foo.bar".equals(hostname))
                return "v=spf1 +a:myipv6a.record -all";
            if ("spf22-test.foo.bar".equals(hostname))
                throw new TempErrorException("DNS Server returns temperror");          
        }
        throw new IllegalStateException("Mock data not available");
    }

    public List getLocalDomainNames() {
        throw new IllegalStateException("Mock data not available");
    }

    public List getAAAARecords(String strServer, int mask)
            throws NoneException, PermErrorException, TempErrorException {
        if ("myipv6a.record".equals(strServer))      
            return getAddressList("FEDC:BA98:7654:3210:FEDC:BA98:7654:3210",mask);
        throw new IllegalStateException("Mock data not available");
    }

    public List getARecords(String strServer, int mask) throws NoneException,
            PermErrorException, TempErrorException {
        throw new IllegalStateException("Mock data not available");
    }

    public String getTxtCatType(String strServer) throws NoneException,
            PermErrorException, TempErrorException {
        if ("".equals(strServer))
            throw new NoneException("No TXTRecord found for: " + strServer);
        if ("spf14-test.foo.bar".equals(strServer))
            return "include.explanation";
        if ("spf16-test.foo.bar".equals(strServer))
            return "redirect.explanation";
        if ("spf17-test.foo.bar".equals(strServer))
            return "original.explanation";
        
        throw new IllegalStateException("Mock data not available for: " + strServer);
    }

    public List getPTRRecords(String ipAddress) throws PermErrorException,
            NoneException, TempErrorException {
        throw new IllegalStateException("Mock data not available");
    }

    public List getMXRecords(String domainName, int mask)
            throws PermErrorException, NoneException, TempErrorException {
        throw new IllegalStateException("Mock data not available");
    }

    public void setTimeOut(int timeOut) {
        // MOCK
    }
    
    public List getAddressList(String list, int mask) throws PermErrorException {
        if (list == null || "".equals(list)) {
            return new ArrayList();
        }
        String[] s = list.split(",");
        IPAddr[] ips = new IPAddr[s.length];
        for (int i = 0; i < s.length; i++) {
            ips[i] = IPAddr.getAddress(s[i], mask);
        }
        return new ArrayList(Arrays.asList(ips));
    }
}