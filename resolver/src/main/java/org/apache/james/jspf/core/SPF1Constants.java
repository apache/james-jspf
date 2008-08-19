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


package org.apache.james.jspf.core;

/**
 * Interface which holds Constants for SPF
 */
public interface SPF1Constants {

    /**
     * Qualifier for PASS
     */
    public static final String PASS = "+";

    /**
     * Qualifier for NEUTRAL
     */
    public static final String NEUTRAL = "?";

    /**
     * Qualifier for FAIL
     */
    public static final String FAIL = "-";

    /**
     * Qualifier for SOFTFAIL
     */
    public static final String SOFTFAIL = "~";

    /**
     * The valid SPF_VERSION identifier
     */
    public static final String SPF_VERSION1 = "v=spf1";

}