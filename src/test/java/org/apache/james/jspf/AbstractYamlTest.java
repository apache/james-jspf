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
import org.apache.james.jspf.core.SPFRecordParser;
import org.apache.james.jspf.parser.DefaultSPF1Parser;
import org.apache.james.jspf.parser.DefaultTermsFactory;
import org.apache.james.jspf.wiring.DNSServiceEnabled;
import org.apache.james.jspf.wiring.LogEnabled;
import org.apache.james.jspf.wiring.SPFCheckEnabled;
import org.apache.james.jspf.wiring.WiringService;
import org.jvyaml.Constructor;
import org.jvyaml.DefaultYAMLFactory;
import org.jvyaml.YAMLFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import junit.framework.TestCase;

public abstract class AbstractYamlTest extends TestCase {

    SPFYamlTestSuite data;
    String test;
    protected Logger log;
    protected static SPF spf;
    protected static SPFRecordParser parser;
    private static DNSService dns;

    protected AbstractYamlTest(SPFYamlTestSuite def, String test) {
        super(def.getComment()+" #"+test);
        this.data = def;
        this.test = test;
    }

    protected abstract String getFilename();

    protected List internalLoadTests(String filename) throws IOException {
        return loadTests(filename);
    }

    protected AbstractYamlTest(String name) throws IOException {
        super(name);
        List tests = internalLoadTests(getFilename());
        Iterator i = tests.iterator();
        while (i.hasNext() && data == null) {
            SPFYamlTestSuite def = (SPFYamlTestSuite) i.next();
            Iterator j = def.getTests().keySet().iterator();
            while (j.hasNext() && data == null) {
                String test = (String) j.next();
                if (name.equals(def.getComment()+ " #"+test)) {
                    data = def;
                    this.test = test;
                }
            }
        }
        assertNotNull(data);
        assertNotNull(test);
    }

    public static List loadTests(String filename) throws IOException {
        List tests = new ArrayList();
    
        //InputStream is = SPFYamlTest.class.getResourceAsStream("pyspf-tests.yml");
        InputStream is = SPFYamlTest.class.getResourceAsStream(filename);
        
        Reader br = new BufferedReader(new InputStreamReader(is)) {
    
            public int read(char[] arg0) throws IOException {
                int rl = super.read(arg0);
                return rl;
            }
            
        };
        
        YAMLFactory fact = new DefaultYAMLFactory();
        
        Constructor ctor = fact.createConstructor(fact.createComposer(fact.createParser(fact.createScanner(br)),fact.createResolver()));
        int i = 1;
        while(ctor.checkData()) {
            Object o = ctor.getData();
            if (o instanceof HashMap) {
              HashMap m = (HashMap) o;
              SPFYamlTestSuite ts = new SPFYamlTestSuite(m, i);
              tests.add(ts);
            }
            i++;
        }
    
        return tests;
    }

    protected void runTest() throws Throwable {
        String next = test;
        HashMap currentTest = (HashMap) data.getTests().get(next);

        if (log == null) {
                log = new ConsoleLogger();
        }

        Logger testLogger = log.getChildLogger("test");
        testLogger.info("TESTING "+next+": "+currentTest.get("description"));
    
        if (parser == null) {
            /* PREVIOUS SLOW WAY 
            enabledServices = new WiringServiceTable();
            enabledServices.put(LogEnabled.class, log);
            */
            parser = new DefaultSPF1Parser(log.getChildLogger("parser"), new DefaultTermsFactory(log.getChildLogger("termsfactory"), new WiringService() {

                public void wire(Object component) throws WiringServiceException {
                    if (component instanceof LogEnabled) {
                        String[] path = component.getClass().toString().split("\\.");
                        ((LogEnabled) component).enableLogging(log.getChildLogger("dep").getChildLogger(path[path.length-1].toLowerCase()));
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
        dns = new LoggingDNSService(getDNSService(), log.getChildLogger("dns"));
        spf = new SPF(dns, parser, log.getChildLogger("spf"));
        /* PREVIOUS SLOW WAY 
        // we add this after the creation because it is a loop reference
        enabledServices.remove(DNSServiceEnabled.class);
        enabledServices.put(DNSServiceEnabled.class, getDNSService());
        enabledServices.remove(SPFCheckEnabled.class);
        enabledServices.put(SPFCheckEnabled.class, spf);
        */

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
        String resultSPF = res.getResult();
        
        if (currentTest.get("result") instanceof String) {
            assertEquals("Test "+next+" ("+currentTest.get("description")+") failed. Returned: "+res.getResult()+" Expected: "+currentTest.get("result")+" [["+res.getResult()+"||"+res.getHeaderText()+"]]", currentTest.get("result"), res.getResult());
        } else {
            ArrayList results = (ArrayList) currentTest.get("result");
            boolean match = false;
            for (int i = 0; i < results.size(); i++) {
                if (results.get(i).equals(resultSPF)) match = true;
                // testLogger.debug("checking "+resultSPF+" against allowed result "+results.get(i));
            }
            assertTrue(match);
        }
        
        if (currentTest.get("explanation") != null) {
            
            // Check for our default explanation!
            if (currentTest.get("explanation").equals("DEFAULT") || currentTest.get("explanation").equals("postmaster") ) {
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
    
        testLogger.info("PASSED. Result="+res.getResult()+" Explanation="+res.getExplanation()+" Header="+res.getHeaderText());
        
    }

    /**
     * @return
     */
    protected DNSService getDNSService() {
        SPFYamlDNSService yamlDNSService = new SPFYamlDNSService((HashMap) data.getZonedata());
        return yamlDNSService;
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

        public List getRecords(String hostname, int recordType) throws TimeoutException {
            return getRecords(hostname, recordType, 6);
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
                            if (recordType == DNSService.MX) {
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
                                    res.add((String) obj);
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
                        throw new TimeoutException();
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
            case DNSService.A: return "A";
            case DNSService.AAAA: return "AAAA";
            case DNSService.MX: return "MX";
            case DNSService.PTR: return "PTR";
            case DNSService.TXT: return "TXT";
            case DNSService.SPF: return "SPF";
            default: return null;
        }
    }

    protected static class SPFYamlTestSuite {
        public String comment;
        public HashMap tests;
        private HashMap zonedata;
        public String getComment() {
            return comment;
        }
        
        public SPFYamlTestSuite(HashMap source, int i) {
            this.setComment((String) source.get("description"));
            if (this.getComment() == null) {
                this.setComment("Test #"+i); 
            }
            this.setTests((HashMap) source.get("tests"));
            this.setZonedata((HashMap) source.get("zonedata"));
        }
        
        public void setComment(String comment) {
            this.comment = comment;
        }
        public HashMap getTests() {
            return tests;
        }
        public void setTests(HashMap tests) {
            this.tests = tests;
        }
        public HashMap getZonedata() {
            return zonedata;
        }
        public void setZonedata(HashMap zonedata) {
            this.zonedata = new HashMap();
            Set keys = zonedata.keySet();
            for (Iterator i = keys.iterator(); i.hasNext(); ) {
                String hostname = (String) i.next();
                String lowercase = hostname.toLowerCase(Locale.US);
                this.zonedata.put(lowercase, zonedata.get(hostname));
            }
        }
    }

}