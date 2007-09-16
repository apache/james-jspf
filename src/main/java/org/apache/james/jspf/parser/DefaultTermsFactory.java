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

package org.apache.james.jspf.parser;

import org.apache.james.jspf.core.LogEnabled;
import org.apache.james.jspf.core.Logger;
import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.terms.Configuration;
import org.apache.james.jspf.terms.ConfigurationEnabled;
import org.apache.james.jspf.wiring.WiringService;
import org.apache.james.jspf.wiring.WiringServiceException;
import org.apache.james.jspf.wiring.WiringServiceTable;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Properties;

/**
 * The default implementation of the TermsFactory
 */
public class DefaultTermsFactory implements TermsFactory {
    
    private String termFile = "org/apache/james/jspf/parser/jspf.default.terms";
    
    private Collection mechanismsCollection;

    private Collection modifiersCollection;

    private Logger log;
    
    private WiringService wiringService;

    public DefaultTermsFactory(Logger log) {
        this.log = log;
        this.wiringService = new WiringServiceTable();
        ((WiringServiceTable) this.wiringService).put(LogEnabled.class, log);
        init();
    }

    public DefaultTermsFactory(Logger log, WiringService wiringService) {
        this.log = log;
        this.wiringService = wiringService;
        init();
    }

    /**
     * Initialize the factory and the services
     */
    private void init() {
        try {
            InputStream is = Thread.currentThread().getContextClassLoader()
                    .getResourceAsStream(termFile);
            Properties p = new Properties();
            p.load(is);
            String mechs = p.getProperty("mechanisms");
            String mods = p.getProperty("modifiers");
            String[] classes;
            classes = mechs.split(",");
            Class[] knownMechanisms = new Class[classes.length];
            for (int i = 0; i < classes.length; i++) {
                log.debug("Add following class as known mechanismn: "
                        + classes[i]);
                knownMechanisms[i] = Thread.currentThread()
                        .getContextClassLoader().loadClass(classes[i]);
            }
            mechanismsCollection = createTermDefinitionCollection(knownMechanisms);
            classes = mods.split(",");
            Class[] knownModifiers = new Class[classes.length];
            for (int i = 0; i < classes.length; i++) {
                log.debug("Add following class as known modifier: "
                        + classes[i]);
                knownModifiers[i] = Thread.currentThread()
                        .getContextClassLoader().loadClass(classes[i]);
            }
            modifiersCollection = createTermDefinitionCollection(knownModifiers);
    
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Term configuration cannot be found");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(
                    "One configured class cannot be found");
        }
    }


    /**
     * Create a collection of term definitions supported by this factory.
     * 
     * @param classes
     *            classes to analyze
     * @param staticFieldName
     *            static field to concatenate
     * @return map <Class,Pattern>
     */
    private Collection createTermDefinitionCollection(Class[] classes) {
        Collection l = new ArrayList();
        for (int j = 0; j < classes.length; j++) {
            try {
                l.add(new DefaultTermDefinition(classes[j]));
            } catch (Exception e) {
                log.debug("Unable to create the term collection", e);
                throw new IllegalStateException(
                        "Unable to create the term collection");
            }
        }
        return Collections.synchronizedCollection(l);
    }


    /**
     * @see org.apache.james.jspf.parser.TermsFactory#createTerm(org.apache.james.jspf.parser.TermDefinition, org.apache.james.jspf.core.MatcherBasedConfiguration)
     */
    public Object createTerm(Class termDef, Configuration subres) throws PermErrorException, InstantiationException {
        try {
            Object term = termDef.newInstance();
            
            try {
                wiringService.wire(term);
            } catch (WiringServiceException e) {
                throw new InstantiationException(
                        "Unexpected error adding dependencies to term: " + e.getMessage());
            }

            if (term instanceof ConfigurationEnabled) {
                if (subres == null || subres.groupCount() == 0) {
                    ((ConfigurationEnabled) term).config(null);
                } else {
                    ((ConfigurationEnabled) term).config(subres);
                }
            }
            return term;
        } catch (IllegalAccessException e) {
            throw new InstantiationException(
                    "Unexpected error creating term: " + e.getMessage());
        }
    }


    /**
     * @see org.apache.james.jspf.parser.TermsFactory#getMechanismsCollection()
     */
    public Collection getMechanismsCollection() {
        return mechanismsCollection;
    }


    /**
     * @see org.apache.james.jspf.parser.TermsFactory#getModifiersCollection()
     */
    public Collection getModifiersCollection() {
        return modifiersCollection;
    }

}
