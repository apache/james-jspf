/*
 * Created on 18/set/06
 *
 * To change the template for this generated file go to
 * Window - Preferences - Java - Code Generation - Code and Comments
 */
package org.apache.james.jspf;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestSuite;

public class RFC4408YamlTest extends SPFYamlTest {

    private static final String YAMLFILE2 = "rfc4408-tests.yml";

    /**
     * @param name
     * @throws IOException
     */
    public RFC4408YamlTest(String name) throws IOException {
        super(name);
    }

    protected RFC4408YamlTest(SPFYamlTestSuite def, String test) {
        super(def, test);
    }

    protected String getFilename() {
        return YAMLFILE2;
    }

    public static Test suite() throws IOException {
        return new RFC4408Suite();
    }

    protected List internalLoadTests(String filename) throws IOException {
        return loadTests(filename);
    }

    static class RFC4408Suite extends TestSuite {

        public RFC4408Suite() throws IOException {
            super();
            List tests = loadTests(YAMLFILE2);
            Iterator i = tests.iterator();
            while (i.hasNext()) {
                SPFYamlTestSuite o = (SPFYamlTestSuite) i.next();
                Iterator ttt = o.getTests().keySet().iterator();
                while (ttt.hasNext()) {
                    addTest(new RFC4408YamlTest(o,(String) ttt.next()));
                }
            }
        }

    }

}
