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

import org.apache.james.jspf.core.DNSService;
import org.apache.james.jspf.executor.AsynchronousSPFExecutor;
import org.apache.james.jspf.executor.SPFExecutor;
import org.apache.james.jspf.executor.SynchronousSPFExecutor;

public class DefaultSPF extends SPF {
    /**
     * Creates an instance with the default dns resolver and a SynchronousSPFExecutor
     *
     * @see #createAsync()
     * @see #createSync()
     * @see SPF#SPF(DNSService, SPFExecutor)
     */
    public DefaultSPF() {
        super(new DNSServiceXBillImpl());
    }

    /**
     * Creates an instance of {@link SPF} with a default dns resolver and a {@link SynchronousSPFExecutor}
     *
     * @see #createAsync()
     * @see SPF#SPF(DNSService, SPFExecutor)
     * @return SPF
     */
    public static SPF createSync() {
        return new SPF(new DNSServiceXBillImpl());
    }

    /**
     * Creates an instance of {@link SPF} with a default dns resolver and a {@link AsynchronousSPFExecutor}
     *
     * @see #createSync()
     * @see SPF#SPF(DNSService, SPFExecutor)
     * @return SPF
     */
    public static SPF createAsync() {
        DNSServiceXBillImpl dnsService = new DNSServiceXBillImpl();
        return new SPF(dnsService, new AsynchronousSPFExecutor(dnsService));
    }
}
