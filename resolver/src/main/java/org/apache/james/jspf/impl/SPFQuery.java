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

package org.apache.james.jspf.impl;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.apache.james.jspf.core.exceptions.SPFErrorConstants;
import org.apache.james.jspf.executor.SPFResult;

/**
 * This class is used for commandline usage of JSPF
 * 
 */
public class SPFQuery {

    private final static int PASS_RCODE = 0;

    private final static int FAIL_RCODE = 1;

    private final static int SOFTFAIL_RCODE = 2;

    private final static int NEUTRAL_RCODE = 3;

    private final static int TEMP_ERROR_RCODE = 4;

    private final static int PERM_ERROR_RCODE = 5;

    private final static int NONE_RCODE = 6;

    private final static int UNKNOWN_RCODE = 255;

    private final static String CMD_IP = "ip";
    private final static char CHAR_IP = 'i';

    private final static String CMD_SENDER = "sender";
    private final static char CHAR_SENDER = 's';

    private final static String CMD_HELO = "helo";
    private final static char CHAR_HELO = 'h';

    private final static String CMD_DEBUG = "debug";
    private final static char CHAR_DEBUG = 'd';

    private final static String CMD_VERBOSE = "verbose";
    private final static char CHAR_VERBOSE = 'v';

    private final static String CMD_DEFAULT_EXP = "default-explanation";
    private final static char CHAR_DEFAULT_EXP = 'e';

    private final static String CMD_BEST_GUESS = "enable-best-guess";
    private final static char CHAR_BEST_GUESS = 'b';
    
    private final static String CMD_TRUSTED_FORWARDER = "enable-trusted-forwarder";
    private final static char CHAR_TRUSTED_FORWARDER = 't';

    /**
     * @param args
     *            The commandline arguments to parse
     */
    public static void main(String[] args) {

        String ip = null;
        String sender = null;
        String helo = null;
        String defaultExplanation = null;
        boolean useBestGuess = false;
        boolean useTrustedForwarder = false;

        Options options = generateOptions();
        CommandLineParser parser = new PosixParser();

        try {
            CommandLine line = parser.parse(options, args);

            ip = line.getOptionValue(CHAR_IP);
            sender = line.getOptionValue(CHAR_SENDER);
            helo = line.getOptionValue(CHAR_HELO);
            defaultExplanation = line.getOptionValue(CHAR_DEFAULT_EXP);
            useBestGuess = line.hasOption(CHAR_BEST_GUESS);
            useTrustedForwarder = line.hasOption(CHAR_TRUSTED_FORWARDER);
            // check if all needed values was set
            if (ip != null && sender != null && helo != null) {

                SPF spf = new DefaultSPF();

                // Check if we should set a costum default explanation
                if (defaultExplanation != null) {
                    spf.setDefaultExplanation(defaultExplanation);
                }

                // Check if we should use best guess
                if (useBestGuess == true) {
                    spf.setUseBestGuess(true);
                }
                
                if (useTrustedForwarder == true) {
                    spf.setUseTrustedForwarder(true);
                }

                SPFResult result = spf.checkSPF(ip, sender, helo);
                System.out.println(result.getResult());
                System.out.println(result.getHeader());
                System.exit(getReturnCode(result.getResult()));

            } else {
                usage();
            }
        } catch (ParseException e) {
            usage();
        }
    }

    /**
     * Return the generated Options
     * 
     * @return options
     */
    private static Options generateOptions() {
        Options options = new Options();
        
        OptionBuilder.withLongOpt(CMD_IP);
        OptionBuilder.withValueSeparator('=');
        OptionBuilder.withArgName("ip");
        OptionBuilder.withDescription("Sender IP address");
        OptionBuilder.isRequired();
        OptionBuilder.hasArg();
        options.addOption(OptionBuilder.create(CHAR_IP));
       
        
        OptionBuilder.withLongOpt(CMD_SENDER);
        OptionBuilder.withValueSeparator('=');
        OptionBuilder.withArgName("sender");
        OptionBuilder.withDescription("Sender address");
        OptionBuilder.isRequired();
        OptionBuilder.hasArg();
        options.addOption(OptionBuilder.create(CHAR_SENDER));
        
        OptionBuilder.withLongOpt(CMD_HELO);
        OptionBuilder.withValueSeparator('=');
        OptionBuilder.withArgName("helo");
        OptionBuilder.withDescription("Helo name");
        OptionBuilder.isRequired();
        OptionBuilder.hasArg();
        options.addOption(OptionBuilder.create(CHAR_HELO));
                
        OptionBuilder.withLongOpt(CMD_DEFAULT_EXP);
        OptionBuilder.withValueSeparator('=');
        OptionBuilder.withArgName("expl");
        OptionBuilder.withDescription("Default explanation");
        OptionBuilder.hasArg();  
        options.addOption(OptionBuilder.create(CHAR_DEFAULT_EXP));
                
        OptionBuilder.withLongOpt(CMD_BEST_GUESS);
        OptionBuilder.withArgName("bestguess");
        OptionBuilder.withDescription("Enable 'best guess' rule");
        options.addOption(OptionBuilder.create(CHAR_BEST_GUESS));
               
        OptionBuilder.withLongOpt(CMD_TRUSTED_FORWARDER);
        OptionBuilder.withArgName("trustedfwd");
        OptionBuilder.withDescription("Enable 'trusted forwarder' rule");
        options.addOption(OptionBuilder.create(CHAR_TRUSTED_FORWARDER));

        OptionBuilder.withLongOpt(CMD_DEBUG);
        OptionBuilder.withArgName("debug");
        OptionBuilder.withDescription("Enable debug");
        options.addOption(OptionBuilder.create(CHAR_DEBUG));

        OptionBuilder.withLongOpt(CMD_VERBOSE);
        OptionBuilder.withArgName("verbose");
        OptionBuilder.withDescription("Enable verbose mode");
        options.addOption(OptionBuilder.create(CHAR_VERBOSE));
                
        return options;
    }

    /**
     * Print out the usage
     */
    private static void usage() {
        HelpFormatter hf = new HelpFormatter();
        hf.printHelp("SPFQuery", generateOptions(), true);
        System.exit(UNKNOWN_RCODE);
    }

    /**
     * Return the return code for the result
     * 
     * @param result
     *            The result
     * @return returnCode
     */
    private static int getReturnCode(String result) {

        if (result.equals(SPFErrorConstants.PASS_CONV)) {
            return PASS_RCODE;
        } else if (result.equals(SPFErrorConstants.FAIL_CONV)) {
            return FAIL_RCODE;
        } else if (result.equals(SPFErrorConstants.SOFTFAIL_CONV)) {
            return SOFTFAIL_RCODE;
        } else if (result.equals(SPFErrorConstants.NEUTRAL_CONV)) {
            return NEUTRAL_RCODE;
        } else if (result.equals(SPFErrorConstants.TEMP_ERROR_CONV)) {
            return TEMP_ERROR_RCODE;
        } else if (result.equals(SPFErrorConstants.PERM_ERROR_CONV)) {
            return PERM_ERROR_RCODE;
        } else if (result.equals(SPFErrorConstants.NONE_CONV)) {
            return NONE_RCODE;
        }

        return UNKNOWN_RCODE;
    }

}
