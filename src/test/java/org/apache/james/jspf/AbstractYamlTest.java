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

import junit.framework.TestCase;

public abstract class AbstractYamlTest extends TestCase {

    SPFYamlTestSuite data;
    String test;

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
                // System.out.println("<<< "+new String(arg0));
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
        
        System.out.println("testing "+next+": "+currentTest.get("description"));
    
        SPF spf = new SPF(getDNSService(), new ConsoleLogger());
        
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
            assertEquals("Test "+next+" ("+currentTest.get("description")+") failed. Returned: "+res.getResult()+" Expected: "+currentTest.get("result")+" [["+res.getResultChar()+"||"+res.getHeaderText()+"]]", currentTest.get("result"), res.getResult());
        } else {
            ArrayList results = (ArrayList) currentTest.get("result");
            boolean match = false;
            for (int i = 0; i < results.size(); i++) {
                if (results.get(i).equals(resultSPF)) match = true;
                System.err.println("checking "+results.get(i)+" => "+resultSPF);
            }
            assertTrue(match);
        }
        
        if (currentTest.get("explanation") != null) {
            
            // Check for our default explanation!
            if (currentTest.get("explanation").equals("DEFAULT") || currentTest.get("explanation").equals("postmaster") ) {
                assertTrue(res.getExplanation().startsWith("http://www.openspf.org/why.html?sender="));
            } else {
                assertEquals(currentTest.get("explanation"),res.getExplanation());
            }
    
        }
    
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

        public List getAAAARecords(String strServer) throws NoneException, PermErrorException, TempErrorException {
            ArrayList res = new ArrayList();
            if (zonedata.get(strServer) != null) {
                List l = (List) zonedata.get(strServer);
                Iterator i = l.iterator();

                while (i.hasNext()) {
                    HashMap hm = (HashMap) i.next();
                    if (hm.get("AAAA") != null) {
                        String a = (String) hm.get("AAAA");
                        res.add(IPAddr.getAddress(a));
                    }
                }
            }
            if (res.size() > 0 ) return res;
            
            throw new NoneException("No AAAA Record found");
        }

        public List getARecords(String strServer) throws NoneException, PermErrorException, TempErrorException {
            ArrayList res = new ArrayList();
       
            if (zonedata.get(strServer) != null) {
                List l = (List) zonedata.get(strServer);
                Iterator i = l.iterator();
                while (i.hasNext()) {
                    HashMap hm = (HashMap) i.next();
                    if (hm.get("A") != null) {
                        String a = (String) hm.get("A");
                        res.add(IPAddr.getAddress(a));
                        
                    }
                }
            }
            if (res.size() > 0 ) return res;
            
            throw new NoneException("No A Record found for: " + strServer);
        }

        public List getLocalDomainNames() {
            List l = new ArrayList();
            l.add("localdomain.foo.bar");
            return l; 
        }

        public List getMXRecords(String domainName) throws PermErrorException, NoneException, TempErrorException {
            if (zonedata.get(domainName) != null) {
                List l = (List) zonedata.get(domainName);
                Iterator i = l.iterator();
                ArrayList res = new ArrayList();
                while (i.hasNext()) {
                    HashMap hm = (HashMap) i.next();
                    if (hm.get("MX") != null) {
                        List mxList = (List) hm.get("MX");
                         
                        Iterator mxs = mxList.iterator();
                
                        while (mxs.hasNext()) {
                            // skip the MX priority
                            mxs.next();
                            String mx = (String) mxs.next();
                           
                            // resolv the record
                            List records = getARecords(mx);
                            for (int i2 = 0; i2 < records.size();i2++ ) {
                                res.add(records.get(i2));
                            }
                        }
                    }
                }
                // check if the maximum lookup count is reached
                if (recordLimit > 0 && res.size() > recordLimit) throw new PermErrorException("Maximum MX lookup count reached");

                return res.size() > 0 ? res : null;
            }
            throw new NoneException("No MX Record found");
        }

        public List getPTRRecords(String ipAddress) throws PermErrorException, NoneException, TempErrorException {
            ArrayList res = new ArrayList();
            
            if (zonedata.get(ipAddress) != null) {
                List l = (List) zonedata.get(ipAddress);
                Iterator i = l.iterator();
                while (i.hasNext()) {
                    HashMap hm = (HashMap) i.next();
                    if (hm.get("PTR") != null) {
                        String a = (String) hm.get("PTR");
                        res.add(a);
                        
                    }
                }
            }
            if (res.size() > 0 ) return res;
            
            throw new NoneException("No PTR Record found: "+ipAddress);
        }

        public String getSpfRecord(String hostname, String spfVersion) throws PermErrorException, NoneException, TempErrorException {
            if (hostname.endsWith(".")) hostname = hostname.substring(0, hostname.length()-1);
            if (zonedata.get(hostname) != null) {
                List l = (List) zonedata.get(hostname);
                Iterator i = l.iterator();
                String res = null;
                boolean SPFexists = false;
                while (i.hasNext()) {
                    Object o = i.next();
                    if (o instanceof HashMap) {
                        HashMap hm = (HashMap) o;
                        if (hm.get("SPF") != null) {
                            SPFexists = true;
                            String spfrecord = (String) hm.get("SPF");
                            if (spfrecord.startsWith(spfVersion+" ") || spfrecord.equals(spfVersion)) {
                                if (res != null) {
                                    throw new PermErrorException("Multiple SPF records!");
                                } else {
                                    res = spfrecord;
                                }
                            } else {
                                System.err.println("#####1 unmatched: "+spfrecord);
                            }
                        }
                    } else {
                        System.err.println("[[[[[[[[[[[[[[[[[[[[1 "+o.getClass().toString()+" ! "+o);
                    }
                }
                if (!SPFexists) {
                    i = l.iterator();
                    while (i.hasNext()) {
                        Object o = i.next();
                        if (o instanceof HashMap) {
                            HashMap hm = (HashMap) o;
                            if (hm.get("TXT") != null) {
                                String spfrecord = (String) hm.get("TXT");
                                if (spfrecord.startsWith(spfVersion+" ") || spfrecord.equals(spfVersion)) {
                                    if (res != null) {
                                        throw new PermErrorException("Multiple TXT records!");
                                    } else {
                                        res = spfrecord;
                                    }
                                } else {
                                    System.err.println("#####2 unmatched: "+spfrecord);
                                }
                            }
                        } else if (o.toString().equals("TIMEOUT")) {
                            throw new TempErrorException("Timeout");
                        } else {
                            System.err.println("[[[[[[[[[[[[[[[[[[[[2 "+o.getClass().toString()+" ! "+o);
                        }
                    }
                }
                if (res != null) return res;
            }
            int p = hostname.indexOf(".");
            if (p > 0) {
                hostname = hostname.substring(p+1);
                if (zonedata.get(hostname) != null) {
                    if (((List) zonedata.get(hostname)).iterator().next().equals("TIMEOUT")) {
                        throw new NoneException("TIMEOUT");
                    }
                }
            }
            throw new NoneException("No SPF Record for : " + hostname);
        }

        public String getTxtCatType(String strServer) throws NoneException, PermErrorException, TempErrorException {
            String res = null;
            if (strServer.endsWith(".")) strServer = strServer.substring(0, strServer.length()-1);
            if (zonedata.get(strServer) != null) {
                List l = (List) zonedata.get(strServer);
                Iterator i = l.iterator();

                while (i.hasNext()) {
                    HashMap hm = (HashMap) i.next();
                    if (hm.get("TXT") != null) {
                        String spfrecord = (String) hm.get("TXT");
                        if (res != null) res+=" "; else res = "";
                        res += spfrecord;
                    }
                }

            }
            return res;
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
    }


    protected static class SPFYamlTestSuite {
        public String comment;
        public HashMap tests;
        public HashMap zonedata;
        public String getComment() {
            return comment;
        }
        
        public SPFYamlTestSuite(HashMap source, int i) {
            this.comment = (String) source.get("description");
            if (this.comment == null) {
                this.comment = "Test #"+i; 
            }
            this.tests = (HashMap) source.get("tests");
            this.zonedata = (HashMap) source.get("zonedata");
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
            this.zonedata = zonedata;
        }
    }

}