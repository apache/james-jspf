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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

public class WiringServiceTableTest {

    public interface NameEnabled {
        void enableName(String name);
    }

    public interface TwoMethodsEnabled {
        void first(String value);

        void second(String value);
    }

    public static class Component implements NameEnabled, TwoMethodsEnabled {
        String name;
        String other;

        public void enableName(String name) {
            if ("boom".equals(name)) {
                throw new IllegalStateException("boom");
            }
            this.name = name;
        }

        public void first(String value) {
            other = value;
        }

        public void second(String value) {
            other = value;
        }
    }

    @Test
    public void shouldCallTheSetterOfTheEnablingInterface() throws Exception {
        WiringServiceTable table = new WiringServiceTable();
        table.put(NameEnabled.class, "a");
        Component component = new Component();

        table.wire(component);

        assertEquals("a", component.name);
    }

    @Test
    public void shouldWireTheServiceRegisteredLast() throws Exception {
        WiringServiceTable table = new WiringServiceTable();
        table.put(NameEnabled.class, "a");
        table.wire(new Component());
        table.put(NameEnabled.class, "b");
        Component component = new Component();

        table.wire(component);

        assertEquals("b", component.name);
    }

    @Test
    public void shouldIgnoreAnInterfaceWithSeveralMethods() throws Exception {
        WiringServiceTable table = new WiringServiceTable();
        table.put(TwoMethodsEnabled.class, "a");
        Component component = new Component();

        table.wire(component);

        assertNull(component.other);
    }

    @Test
    public void shouldReportAFailingSetter() {
        WiringServiceTable table = new WiringServiceTable();
        table.put(NameEnabled.class, "boom");

        try {
            table.wire(new Component());
            fail("expected a WiringServiceException");
        } catch (WiringServiceException e) {
            assertTrue(e.getMessage().contains("NameEnabled"));
        }
    }
}
