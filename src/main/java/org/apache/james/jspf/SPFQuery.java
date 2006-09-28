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


package org.apache.james.jspf;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
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
    
    private final static String CMD_IP = "ip";
    
    private final static String CMD_SENDER = "sender";
    
    private final static String CMD_HELO = "helo";
    
    private final static String CMD_DEBUG = "debug";
    
    private final static String CMD_VERBOSE = "verbose";

    private final static String CMD_DEFAULT_EXP =  "defaultexplanation";
    
    private final static String CMD_BEST_GUESS =  "usebestguess";
      
    private static Logger logger = Logger.getRootLogger();


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

        SimpleLayout layout = new SimpleLayout();
        ConsoleAppender consoleAppender = new ConsoleAppender(layout);
        logger.addAppender(consoleAppender);

        logger.setLevel(Level.ERROR);

        Options options = generateOptions();
        CommandLineParser parser = new PosixParser();

        try {
            CommandLine line = parser.parse(options, args);
            
            ip = line.getOptionValue(CMD_IP);
            sender = line.getOptionValue(CMD_SENDER);
            helo = line.getOptionValue(CMD_HELO);
            defaultExplanation = line.getOptionValue(CMD_DEFAULT_EXP);
            useBestGuess = line.hasOption(CMD_BEST_GUESS);

            // check if all needed values was set
            if (ip != null && sender != null && helo != null) {

                if (line.hasOption(CMD_DEBUG))
                    logger.setLevel(Level.DEBUG);
                if (line.hasOption(CMD_VERBOSE))
                    logger.setLevel(Level.TRACE);

                SPF spf = new SPF(new Log4JLogger(logger));

                // Check if we should set a costum default explanation
                if (defaultExplanation != null) {
                    spf.setDefaultExplanation(defaultExplanation);
                }

                // Check if we should use best guess
                if (useBestGuess == true) {
                    spf.setUseBestGuess(true);
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
        options.addOption(OptionBuilder.withLongOpt(CMD_IP).withValueSeparator('=').hasArg().create());
        options.addOption(OptionBuilder.withLongOpt(CMD_SENDER).withValueSeparator('=').hasArg().create());
        options.addOption(OptionBuilder.withLongOpt(CMD_HELO).withValueSeparator('=').hasArg().create());
        options.addOption(OptionBuilder.withLongOpt(CMD_DEFAULT_EXP).withValueSeparator('=').hasArg().create());
        options.addOption(OptionBuilder.withLongOpt(CMD_BEST_GUESS).create());
        options.addOption(OptionBuilder.withLongOpt(CMD_DEBUG).create());
        options.addOption(OptionBuilder.withLongOpt(CMD_VERBOSE).create());
        return options;
    }

    /**
     * Print out the usage
     */
    private static void usage() {      
        //TODO: Use HelpFormatter for printing usage
        System.out.println("Usage: java -jar jspf-x.jar --" + CMD_IP + "=192.168.100.1 --" + CMD_SENDER + "=postmaster@foo.bar --"
                        + CMD_HELO + "=foo.bar [--"  + CMD_DEFAULT_EXP+ "=\"explanation String\"] [--" +CMD_BEST_GUESS+ "] "+ CMD_DEBUG + "] [--" + CMD_VERBOSE+ "]");
        System.exit(UNKNOWN_RCODE);
    }
    
    
    /**
     * Return the return code for the result
     * 
     * @param result The result 
     * @return returnCode
     */
    private static int getReturnCode(String result) {
        
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
