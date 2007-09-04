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

package org.apache.james.jspf.dns;

import java.util.List;


/**
 * Queue implementation which is used to manage IResponse
 *
 */
public interface IResponseQueue extends List {
    
    /**
     * Return the last IResponse in the queue. If the queue is empty it will
     * wait until a IResponse was added
     * 
     * @return response
     */
    public IResponse removeResponse();
    
    /**
     *  Add the given Response to the end of the queue. 
     *  
     * @param r
     */
    public void insertResponse(IResponse r);

}
