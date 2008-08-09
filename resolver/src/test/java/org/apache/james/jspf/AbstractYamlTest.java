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
import org.apache.james.jspf.core.DNSServiceEnabled;
import org.apache.james.jspf.core.LogEnabled;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.MacroExpand;
import org.apache.james.jspf.core.MacroExpandEnabled;
import org.apache.james.jspf.core.SPFCheckEnabled;
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.core.exceptions.TimeoutException;
import org.apache.james.jspf.dnsserver.DNSTestingServer;
import org.apache.james.jspf.executor.SPFExecutor;
import org.apache.james.jspf.executor.SPFResult;
import org.apache.james.jspf.executor.StagedMultipleSPFExecutor;
import org.apache.james.jspf.executor.SynchronousSPFExecutor;
import org.apache.james.jspf.impl.DNSJnioAsynchService;
import org.apache.james.jspf.impl.DNSServiceAsynchSimulator;
import org.apache.james.jspf.impl.DNSServiceXBillImpl;
import org.apache.james.jspf.impl.DefaultTermsFactory;
import org.apache.james.jspf.impl.SPF;
import org.apache.james.jspf.parser.RFC4408SPF1Parser;
import org.apache.james.jspf.wiring.WiringService;
import org.apache.james.jspf.wiring.WiringServiceException;
import org.xbill.DNS.Cache;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedNonblockingResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.LookupAsynch;
import org.xbill.DNS.Name;
import org.xbill.DNS.NonblockingResolver;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TextParseException;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import junit.framework.AssertionFailedError;
import junit.framework.TestCase;

public abstract class AbstractYamlTest extends TestCase {

    private static final int FAKE_SERVER_PORT = 31347;
    protected static final int TIMEOUT = 10;
    protected static final int MOCK_SERVICE = 2;
    protected static final int FAKE_SERVER = 1;
    protected static final int REAL_SERVER = 3;
    private int dnsServiceMockStyle = MOCK_SERVICE;

    protected static final int SYNCHRONOUS_EXECUTOR = 1;
    protected static final int STAGED_EXECUTOR = 2;
    protected static final int STAGED_EXECUTOR_MULTITHREADED = 3;
    protected static final int STAGED_EXECUTOR_DNSJNIO = 4;
    private int spfExecutorType = SYNCHRONOUS_EXECUTOR;

    SPFYamlTestDescriptor data;
    String test;
    protected Logger log;
    private SPFExecutor executor;
    protected static MacroExpand macroExpand;
    protected static SPF spf;
    protected static SPFYamlTestDescriptor prevData;
    protected static SPFRecordParser parser;
    private static DNSService dns;
    protected static DNSTestingServer dnsTestServer;

    protected AbstractYamlTest(SPFYamlTestDescriptor def, String test) {
        super(def.getComment()+" #"+test);
        this.data = def;
        this.test = test;
    }

    protected AbstractYamlTest(SPFYamlTestDescriptor def) {
        super(def.getComment()+" #COMPLETE!");
        this.data = def;
        this.test = null;
    }

    protected abstract String getFilename();

    protected AbstractYamlTest(String name) throws IOException {
        super(name);
        List tests = SPFYamlTestDescriptor.loadTests(getFilename());
        Iterator i = tests.iterator();
        while (i.hasNext() && data == null) {
            SPFYamlTestDescriptor def = (SPFYamlTestDescriptor) i.next();
            if (name.equals(def.getComment()+" #COMPLETE!")) {
                data = def;
                this.test = null;
            } else {
                Iterator j = def.getTests().keySet().iterator();
                while (j.hasNext() && data == null) {
                    String test = (String) j.next();
                    if (name.equals(def.getComment()+ " #"+test)) {
                        data = def;
                        this.test = test;
                    }
                }
            }
        }
        assertNotNull(data);
        // assertNotNull(test);
    }

    protected void runTest() throws Throwable {

        if (log == null) {
                log = new ConsoleLogger(ConsoleLogger.LEVEL_DEBUG, "root");
        }
        
        log.info("Running test: "+getName()+" ...");

        if (parser == null) {
            /* PREVIOUS SLOW WAY 
            enabledServices = new WiringServiceTable();
            enabledServices.put(LogEnabled.class, log);
            */
            parser = new RFC4408SPF1Parser(log.getChildLogger("parser"), new DefaultTermsFactory(log.getChildLogger("termsfactory"), new WiringService() {

                public void wire(Object component) throws WiringServiceException {
                    if (component instanceof LogEnabled) {
                        String[] path = component.getClass().toString().split("\\.");
                        ((LogEnabled) component).enableLogging(log.getChildLogger("dep").getChildLogger(path[path.length-1].toLowerCase()));
                    }
                    if (component instanceof MacroExpandEnabled) {
                        ((MacroExpandEnabled) component).enableMacroExpand(macroExpand);
                    }
                    if (component instanceof DNSServiceEnabled) {
                        ((DNSServiceEnabled) component).enableDNSService(dns);
                    }
                    if (component instanceof SPFCheckEnabled) {
                        ((SPFCheckEnabled) component).enableSPFChecking(spf);
                    }
                }
                
            }));
        }
        if (this.data != AbstractYamlTest.prevData) {
            dns = new LoggingDNSService(getDNSService(), log.getChildLogger("dns"));
            AbstractYamlTest.prevData = this.data;
        }
        macroExpand = new MacroExpand(log.getChildLogger("macroExpand"), dns);
        if (getSpfExecutorType() == SYNCHRONOUS_EXECUTOR) {  // synchronous
            executor = new SynchronousSPFExecutor(log, dns);
        } else if (getSpfExecutorType() == STAGED_EXECUTOR || getSpfExecutorType() == STAGED_EXECUTOR_MULTITHREADED){
            executor = new StagedMultipleSPFExecutor(log, new DNSServiceAsynchSimulator(dns, getSpfExecutorType() == STAGED_EXECUTOR_MULTITHREADED));
        } else if (getSpfExecutorType() == STAGED_EXECUTOR_DNSJNIO) {
            
            // reset cache between usages of the asynchronous lookuper
            LookupAsynch.setDefaultCache(new Cache(), DClass.IN);
            // reset cache between usages of the asynchronous lookuper
            LookupAsynch.getDefaultCache(DClass.IN).clearCache();

            try {
                ExtendedNonblockingResolver resolver;
                
                if (getDnsServiceMockStyle() == FAKE_SERVER) {
                    NonblockingResolver nonblockingResolver = new NonblockingResolver("127.0.0.1");
                    resolver = ExtendedNonblockingResolver.newInstance(new NonblockingResolver[] {nonblockingResolver});
                    nonblockingResolver.setPort(FAKE_SERVER_PORT);
                    nonblockingResolver.setTCP(false);
                } else if (getDnsServiceMockStyle() == REAL_SERVER) {
                    resolver = ExtendedNonblockingResolver.newInstance();
                    Resolver[] resolvers = resolver.getResolvers();
                    for (int i = 0; i < resolvers.length; i++) {
                        resolvers[i].setTCP(false);
                    }
                } else {
                    throw new IllegalStateException("DnsServiceMockStyle "+getDnsServiceMockStyle()+" is not supported when STAGED_EXECUTOR_DNSJNIO executor style is used");
                }
                
                DNSJnioAsynchService jnioAsynchService = new DNSJnioAsynchService(resolver);
                jnioAsynchService.setTimeout(TIMEOUT);
                executor = new StagedMultipleSPFExecutor(log, jnioAsynchService);

            } catch (UnknownHostException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }

        } else {
            throw new UnsupportedOperationException("Unknown executor type");
        }
        spf = new SPF(dns, parser, log.getChildLogger("spf"), macroExpand, executor);

        if (test != null) {
            String next = test;
            SPFResult res = runSingleTest(next);
            verifyResult(next, res);
        } else {
            Map queries = new HashMap();
            for (Iterator i = data.getTests().keySet().iterator(); i.hasNext(); ) {
                String next = (String) i.next();
                SPFResult res = runSingleTest(next);
                queries.put(next, res);
            }
            AssertionFailedError firstError = null; 
            for (Iterator i = queries.keySet().iterator(); i.hasNext(); ) {
                String next = (String) i.next();
                try {
                    verifyResult(next, (SPFResult) queries.get(next));
                } catch (AssertionFailedError e) {
                    log.getChildLogger(next).info("FAILED. "+e.getMessage()+" ("+getName()+")", e.getMessage()==null ? e : null);
                    if (firstError == null) firstError = e;
                }
            }
            if (firstError != null) throw firstError;
        }
        
    }

    private SPFResult runSingleTest(String testName) {
        HashMap currentTest = (HashMap) data.getTests().get(testName);
        Logger testLogger = log.getChildLogger(testName);
        testLogger.info("TESTING "+testName+": "+currentTest.get("description"));

        String ip = null;
        String sender = null;
        String helo = null;
    
        if (currentTest.get("helo") != null) {
            helo = (String) currentTest.get("helo");
        }
        if (currentTest.get("host") != null) {
            ip = (String) currentTest.get("host");
        }
        if (currentTest.get("mailfrom") != null) {
            sender = (String) currentTest.get("mailfrom");
        } else {
            sender = "";
        }
    
        SPFResult res = spf.checkSPF(ip, sender, helo);
        return res;
    }

    private void verifyResult(String testName, SPFResult res) {
        String resultSPF = res.getResult();
        HashMap currentTest = (HashMap) data.getTests().get(testName);
        Logger testLogger = log.getChildLogger(testName+"-verify");
        if (currentTest.get("result") instanceof String) {
            assertEquals("Test "+testName+" ("+currentTest.get("description")+") failed. Returned: "+resultSPF+" Expected: "+currentTest.get("result")+" [["+resultSPF+"||"+res.getHeaderText()+"]]", currentTest.get("result"), resultSPF);
        } else {
            ArrayList results = (ArrayList) currentTest.get("result");
            boolean match = false;
            for (int i = 0; i < results.size(); i++) {
                if (results.get(i).equals(resultSPF)) match = true;
                // testLogger.debug("checking "+resultSPF+" against allowed result "+results.get(i));
            }
            assertTrue("Test "+testName+" ("+currentTest.get("description")+") failed. Returned: "+resultSPF+" Expected: "+results, match);
        }
        
        if (currentTest.get("explanation") != null) {
            
            // Check for our default explanation!
            if (currentTest.get("explanation").equals("DEFAULT")) {
                assertTrue(res.getExplanation().startsWith("http://www.openspf.org/why.html?sender="));
            } else if (currentTest.get("explanation").equals("cafe:babe::1 is queried as 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa")) {
                // See http://java.sun.com/j2se/1.4.2/docs/api/java/net/Inet6Address.html    
                // For methods that return a textual representation as output value, the full form is used. 
                // Inet6Address will return the full form because it is unambiguous when used in combination with other textual data.
                assertTrue(res.getExplanation().equals("cafe:babe:0:0:0:0:0:1 is queried as 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.E.B.A.B.E.F.A.C.ip6.arpa"));
            } else {
                assertEquals(currentTest.get("explanation"),res.getExplanation());
            }
    
        }
    
        testLogger.info("PASSED. Result="+resultSPF+" Explanation="+res.getExplanation()+" Header="+res.getHeaderText());
    }

    /**
     * @return a Mocked DNSService
     */
    protected DNSService getDNSServiceMockedDNSService() {
        SPFYamlDNSService yamlDNSService = new SPFYamlDNSService(data.getZonedata());
        return yamlDNSService;
    }

    /**
     * @return the right dnsservice according to what the test specialization declares
     */
    protected DNSService getDNSService() {
        switch (getDnsServiceMockStyle()) {
            case MOCK_SERVICE: return getDNSServiceMockedDNSService();
            case FAKE_SERVER: return getDNSServiceFakeServer();
            case REAL_SERVER: return getDNSServiceReal();
            default: 
                throw new UnsupportedOperationException("Unsupported mock style");
        }
    }

    protected int getDnsServiceMockStyle() {
        return dnsServiceMockStyle;
    }

    /**
     * @return a dns resolver pointing to the local fake server
     */
    protected DNSService getDNSServiceFakeServer() {
        Resolver resolver = null;
        try {
            resolver = new SimpleResolver("127.0.0.1");
        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        resolver.setPort(FAKE_SERVER_PORT);
        Lookup.setDefaultResolver(resolver);
        Lookup.setDefaultCache(null, DClass.IN);
        Lookup.setDefaultSearchPath(new Name[] {});

        if (dnsTestServer == null) {
            try {
                dnsTestServer = new DNSTestingServer("0.0.0.0", ""+FAKE_SERVER_PORT);
            } catch (TextParseException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        
        dnsTestServer.setData(data.getZonedata());
        
        DNSServiceXBillImpl serviceXBillImpl = new DNSServiceXBillImpl(log) {

            public List getLocalDomainNames() {
                List l = new ArrayList();
                l.add("localdomain.foo.bar");
                return l; 
            }

        };
        // TIMEOUT 2 seconds
        serviceXBillImpl.setTimeOut(TIMEOUT);
        return serviceXBillImpl;
    }
    
    /**
     * @return a real dns resolver
     */
    protected DNSService getDNSServiceReal() {
        DNSServiceXBillImpl serviceXBillImpl = new DNSServiceXBillImpl(log);
        // TIMEOUT 2 seconds
        serviceXBillImpl.setTimeOut(TIMEOUT);
        return serviceXBillImpl;
    }

    public AbstractYamlTest() {
        super();
    }

    final class SPFYamlDNSService implements DNSService {

        private HashMap zonedata;
        private int recordLimit;

        public SPFYamlDNSService(HashMap zonedata) {
            this.zonedata = zonedata;
            this.recordLimit = 10;
        }

        public List getLocalDomainNames() {
            List l = new ArrayList();
            l.add("localdomain.foo.bar");
            return l; 
        }

        public void setTimeOut(int timeOut) {
            try {
                throw new UnsupportedOperationException("setTimeOut()");
            } catch (UnsupportedOperationException e) {
                e.printStackTrace();
                throw e;
            }
        }

        public int getRecordLimit() {
            return recordLimit;
        }

        public void setRecordLimit(int recordLimit) {
            this.recordLimit = recordLimit;
        }

        public List getRecords(DNSRequest request) throws TimeoutException {
            return getRecords(request.getHostname(), request.getRecordType(), 6);
        }

        public List getRecords(String hostname, int recordType, int depth) throws TimeoutException {
            String type = getRecordTypeDescription(recordType);

            List res;
            
            // remove trailing dot before running the search.
            if (hostname.endsWith(".")) hostname = hostname.substring(0, hostname.length()-1);
            
            // dns search lowercases:
            hostname = hostname.toLowerCase(Locale.US);
            
            if (zonedata.get(hostname) != null) {
                List l = (List) zonedata.get(hostname);
                Iterator i = l.iterator();
                res = new ArrayList();
                while (i.hasNext()) {
                    Object o = i.next();
                    if (o instanceof HashMap) {
                        HashMap hm = (HashMap) o;
                        if (hm.get(type) != null) {
                            if (recordType == DNSRequest.MX) {
                                List mxList = (List) hm.get(type);
    
                                // For MX records we overwrite the result ignoring the priority.
                                Iterator mxs = mxList.iterator();
                                while (mxs.hasNext()) {
                                    // skip the MX priority
                                    mxs.next();
                                    String cname = (String) mxs.next();
                                    res.add(cname);
                                }
                            } else {
                                Object obj = hm.get(type);
                                
                                if (obj instanceof String) {
                                    res.add(obj);
                                } else if (obj instanceof ArrayList) {
                                    ArrayList a = (ArrayList) obj;
                                    StringBuffer sb = new StringBuffer();
                                    
                                    for (int i2 = 0; i2 < a.size(); i2++) {
                                        sb.append(a.get(i2));
                                    }
                                    res.add(sb.toString());
                                }
                            }
                        }
                        if (hm.get("CNAME") != null && depth > 0) {
                            return getRecords((String) hm.get("CNAME"), recordType, depth - 1);
                        }
                    } else if ("TIMEOUT".equals(o)) {
                        throw new TimeoutException("TIMEOUT");
                    } else {
                        throw new IllegalStateException("getRecord found an unexpected data");
                    }
                }
                return res.size() > 0 ? res : null;
            }
            return null;
        }
        
    }

    
    /**
     * Return a string representation of a DNSService record type.
     * 
     * @param recordType the DNSService.CONSTANT type to convert
     * @return a string representation of the given record type
     */
    public static String getRecordTypeDescription(int recordType) {
        switch (recordType) {
            case DNSRequest.A: return "A";
            case DNSRequest.AAAA: return "AAAA";
            case DNSRequest.MX: return "MX";
            case DNSRequest.PTR: return "PTR";
            case DNSRequest.TXT: return "TXT";
            case DNSRequest.SPF: return "SPF";
            default: return null;
        }
    }

    protected int getSpfExecutorType() {
        return spfExecutorType;
    }

}