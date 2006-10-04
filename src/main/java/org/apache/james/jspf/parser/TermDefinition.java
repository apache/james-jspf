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

import java.util.regex.Pattern;

/**
 * A term definition contains everything needed to match and create
 * new Terms implementations.
 */
public interface TermDefinition {

    /**
     * Retrieve the pattern to be used to match a string against this record type.
     * 
     * @return the pattern for this term
     */
    public Pattern getPattern();

    /**
     * The class implementing this Term type.
     * 
     * @return the class object.
     */
    public Class getTermDef();

    /**
     * Return the number of groups to be expected from the pattern of this
     * Term.
     * 
     * @return the number of groups
     */
    public int getMatchSize();

}