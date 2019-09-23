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

import org.apache.james.jspf.core.DNSRequest;
import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.apache.james.jspf.executor.FutureSPFResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class LoggingDNSService implements DNSService {
    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingDNSService.class);

    private DNSService dnsService;

    public LoggingDNSService(DNSService service) {
        this.dnsService = service;
    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#getRecordLimit()
     */
    public int getRecordLimit() {
        return dnsService.getRecordLimit();
    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#setRecordLimit(int)
     */
    public void setRecordLimit(int recordLimit) {
        dnsService.setRecordLimit(recordLimit);
    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#getLocalDomainNames()
     */
    public List<String> getLocalDomainNames() {
        List<String> res = dnsService.getLocalDomainNames();
        StringBuffer logBuff = new StringBuffer();
        logBuff.append("getLocalDomainNames() = ");
        if (res != null) {
            for (int i = 0; i < res.size(); i++) {
                logBuff.append(res.get(i));
                if (i == res.size() - 1) {
                    logBuff.append("");
                } else {
                    logBuff.append(",");
                }
            }
        } else {
            logBuff.append("getLocalDomainNames-ret: null");
        }
        LOGGER.debug(logBuff.toString());
        return res;

    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#setTimeOut(int)
     */
    public void setTimeOut(int timeOut) {
        dnsService.setTimeOut(timeOut);
    }

    /**
     * (non-Javadoc)
     * @see org.apache.james.jspf.core.DNSService#getRecords(org.apache.james.jspf.core.DNSRequest)
     */
    public List<String> getRecords(DNSRequest request) throws TimeoutException {
        try {
            List<String> result = dnsService.getRecords(request);
            StringBuffer logBuff = new StringBuffer();
            logBuff.append("getRecords(" + request.getHostname() + "," + request.getRecordType() + ") = ");
            if (result != null) {
                for (int i = 0; i < result.size(); i++) {
                    logBuff.append(result.get(i));
                    if (i == result.size() - 1) {
                        logBuff.append("");
                    } else {
                        logBuff.append(",");
                    }
                }
            } else {
                logBuff.append("getRecords-ret: null");
            }
            LOGGER.debug(logBuff.toString());
            return result;
        } catch (TimeoutException e) {
            LOGGER.debug("getRecords({}) = TempErrorException[{}]",
                request.getHostname(), e.getMessage());
            throw e;
        }
    }

}