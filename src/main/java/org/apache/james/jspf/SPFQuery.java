/***********************************************************************
 * Copyright (c) 2006 The Apache Software Foundation.                  *
 * All rights reserved.                                                *
 * ------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License"); you *
 * may not use this file except in compliance with the License. You    *
 * may obtain a copy of the License at:                                *
 *                                                                     *
 *     http://www.apache.org/licenses/LICENSE-2.0                      *
 *                                                                     *
 * Unless required by applicable law or agreed to in writing, software *
 * distributed under the License is distributed on an "AS IS" BASIS,   *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or     *
 * implied.  See the License for the specific language governing       *
 * permissions and limitations under the License.                      *
 ***********************************************************************/

package org.apache.james.jspf;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.SimpleLayout;

/**
 * This class is used for commandline usage of JSPF
 * 
 */
public class SPFQuery {

    private final static int PASS_RCODE = 0;
    
    private final static int FAIL_RCODE =  1;
    
    private final static int SOFTFAIL_RCODE = 2;
    
    private final static int NEUTRAL_RCODE = 3;
    
    private final static int TEMP_ERROR_RCODE = 4;
    
    private final static int PERM_ERROR_RCODE = 5;
    
    private final static int NONE_RCODE = 6;
    
    private final static int UNKNOWN_RCODE = 255;

    private static Logger logger = Logger.getRootLogger();

    /**
     * @param args
     *            The commandline arguments to parse
     */
    public static void main(String[] args) {

        String ip = null;
        String sender = null;
        String helo = null;

        SimpleLayout layout = new SimpleLayout();
        ConsoleAppender consoleAppender = new ConsoleAppender(layout);
        logger.addAppender(consoleAppender);

        logger.setLevel(Level.ERROR);

        // Parse the command line arguments
        if (args.length < 3 || args.length > 4) {
            usage();
        } else {
            for (int i = 0; i < args.length; i++) {
                String[] arguments = args[i].split("=");

                if (arguments[0].equals("-ip")) {
                    ip = arguments[1];
                } else if (arguments[0].equals("-sender")) {
                    sender = arguments[1];
                } else if (arguments[0].equals("-helo")) {
                    helo = arguments[1];
                } else if (arguments[0].equals("-debug")) {
                    logger.setLevel(Level.DEBUG);
                } else if (arguments[0].equals("-verbose")) {
                    logger.setLevel(Level.TRACE);
                } else {
                    usage();
                }

            }

            // check if all needed values was set
            if (ip != null && sender != null && helo != null) {
                SPF spf = new SPF();
                SPFResult result = spf.checkSPF(ip, sender, helo);
                System.out.println(result.getResult());
                System.out.println(result.getHeader());
                System.exit(getReturnCode(result.getResult()));
            } else {
                usage();
            }
        }
    }

    /**
     * Print out the usage
     */
    private static void usage() {
        System.out
                .println("Usage: java -jar jspf-x.jar -ip=192.168.100.1 -sender=postmaster@foo.bar -helo=foo.bar [-debug] [-verbose]");
        System.exit(UNKNOWN_RCODE);
    }
    
    
    /**
     * Return the return code for the result
     * 
     * @param result The result 
     * @return returnCode
     */
    public static int getReturnCode(String result) {
        if (result.equals(SPF1Utils.PASS_CONV)) {
            return PASS_RCODE;
        } else if (result.equals(SPF1Utils.FAIL_CONV)) {
            return FAIL_RCODE;
        } else if (result.equals(SPF1Utils.SOFTFAIL_CONV)) {
            return SOFTFAIL_RCODE;
        } else if (result.equals(SPF1Utils.NEUTRAL_CONV)) {
            return NEUTRAL_RCODE;
        } else if (result.equals(SPF1Utils.TEMP_ERROR_CONV)) {
            return TEMP_ERROR_RCODE;
        } else if (result.equals(SPF1Utils.PERM_ERROR_CONV)) {
            return PERM_ERROR_RCODE;
        } else if (result.equals(SPF1Utils.NONE_CONV)) {
            return NONE_RCODE;
        } 
        return UNKNOWN_RCODE;
    }

}
