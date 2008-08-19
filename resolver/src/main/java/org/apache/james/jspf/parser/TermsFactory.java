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

import org.apache.james.jspf.core.exceptions.PermErrorException;
import org.apache.james.jspf.terms.Configuration;

import java.util.Collection;

/**
 * A TermsFactory define the list of known TermDefinition and create new Terms
 * based on its own Definition and a Configuration
 */
public interface TermsFactory {

    /**
     * Create a new term starting from the TermDefinition created by this factory
     * 
     * @param klass the TermDefinition.getTermDef (returned by this factory)
     * @param subres (the configuration)
     * @return the generated object
     * @throws PermErrorException if something goes wrong
     * @throws InstantiationException 
     */
    public Object createTerm(Class klass, Configuration subres)
            throws PermErrorException, InstantiationException;

    /**
     * Return the collection of known Mechanisms
     * 
     * @return a Collection of TermDefinition 
     */
    public Collection getMechanismsCollection();

    /**
     * Return the collection of known Modifiers
     * 
     * @return a Collection of TermDefinition 
     */
    public Collection getModifiersCollection();

}