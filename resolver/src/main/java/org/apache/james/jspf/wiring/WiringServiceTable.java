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

package org.apache.james.jspf.wiring;


import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Hashtable;
import java.util.Iterator;

/**
 * This class associates "Enabling interfaces" to the service that provides the
 * dependency.
 */
public class WiringServiceTable extends Hashtable<Class<?>,Object> implements WiringService {

    private static final long serialVersionUID = -9151935136150279119L;

    /**
     * @see org.apache.james.jspf.wiring.WiringService#wire(java.lang.Object)
     */
    public void wire(Object component) throws WiringServiceException {
        Iterator<Class<?>> i = keySet().iterator();
        while (i.hasNext()) {
            Class<?> enablingClass = i.next();
            if (enablingClass.isInstance(component)) {
                Method[] m = enablingClass.getDeclaredMethods();
                if (m!=null && m.length == 1 && m[0] != null) {
                    try {
                        m[0].invoke(component, new Object[] {get(enablingClass)});
                    } catch (IllegalArgumentException e) {
                        throw new WiringServiceException("Illegal argument invoking enabled service: "+enablingClass.toString(), e);
                    } catch (InvocationTargetException e) {
                        throw new WiringServiceException("Unable to invoke enabled service: "+enablingClass.toString(), e);
                    } catch (IllegalAccessException e) {
                        throw new WiringServiceException("Unable to invoke enabled service: "+enablingClass.toString(), e);
                    }
                }
            }
        }

    }

}
