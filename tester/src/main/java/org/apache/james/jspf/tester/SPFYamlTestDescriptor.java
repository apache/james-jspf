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

package org.apache.james.jspf.tester;

import org.jvyaml.Constructor;
import org.jvyaml.DefaultYAMLFactory;
import org.jvyaml.YAMLFactory;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Describe a test loaded from a YAML file using the format
 * described in the OpenSPF testsuite.
 */
public class SPFYamlTestDescriptor {
    private String comment;
    private Map<String, Map<String, ?>> tests;
    private Map<String, Object> zonedata;
    
    @SuppressWarnings("unchecked")
    public SPFYamlTestDescriptor(Map<String, ?> source, int i) {
        this.setComment((String) source.get("description"));
        if (this.getComment() == null) {
            this.setComment("Test #"+i); 
        }
        this.setTests((Map) source.get("tests"));
        this.setZonedata((Map) source.get("zonedata"));
    }
    
    public String getComment() {
        return comment;
    }
    public void setComment(String comment) {
        this.comment = comment;
    }
    public Map<String,Map<String,?>> getTests() {
        return tests;
    }
    public void setTests(Map<String, Map<String,?>> tests) {
        this.tests = tests;
    }
    public Map<String, ?> getZonedata() {
        return zonedata;
    }
    public void setZonedata(Map<String, Map<?, ?>> zonedata) {
        this.zonedata = new HashMap<String, Object>();
        Set<String> keys = zonedata.keySet();
        for (Iterator<String> i = keys.iterator(); i.hasNext(); ) {
            String hostname = (String) i.next();
            String lowercase = hostname.toLowerCase(Locale.US);
            this.zonedata.put(lowercase, zonedata.get(hostname));
        }
    }
    
    @SuppressWarnings("unchecked")
    public static List<SPFYamlTestDescriptor> loadTests(String filename) throws IOException {
        List<SPFYamlTestDescriptor> tests = new ArrayList<SPFYamlTestDescriptor>();
    
        InputStream is = SPFYamlTestDescriptor.class.getResourceAsStream(filename);
        System.out.println(filename+": "+is);
        
        if (is != null) {
            Reader br = new BufferedReader(new InputStreamReader(is));
            YAMLFactory fact = new DefaultYAMLFactory();
            
            Constructor ctor = fact.createConstructor(fact.createComposer(fact.createParser(fact.createScanner(br)),fact.createResolver()));
            int i = 1;
            while(ctor.checkData()) {
                Object o = ctor.getData();
                if (o instanceof Map<?, ?>) {
                  Map<String, ?> m = (Map<String, ?>) o;
                  SPFYamlTestDescriptor ts = new SPFYamlTestDescriptor(m, i);
                  tests.add(ts);
                }
                i++;
            }
        
            return tests;
        } else {
            throw new FileNotFoundException("Unable to load the file");
        }
    }

}