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

package org.apache.james.jspf.dnsserver;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;
import org.jvyaml.Constructor;
import org.jvyaml.DefaultYAMLFactory;
import org.jvyaml.YAMLFactory;
import org.xbill.DNS.TextParseException;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Set;

public class DNSTestingServerLauncher {

    private static final char CHAR_TESTNAME = 't';

    private static final char CHAR_FILE = 'f';

    private static final char CHAR_PORT = 'p';

    private static final char CHAR_IP = 'i';

    private final static String CMD_IP = "ip";

    private final static String CMD_PORT = "port";

    private final static String CMD_FILE = "file";

    private final static String CMD_TESTNAME = "test";

    /**
     * @param args
     */
    public static void main(String[] args) {
        String ip = null;
        String port = null;
        String file = null;
        String test = null;
        
        Options options = generateOptions();
        CommandLineParser parser = new PosixParser();

        try {
            CommandLine line = parser.parse(options, args);
            
            ip = line.getOptionValue(CHAR_IP);
            port = line.getOptionValue(CHAR_PORT);
            file = line.getOptionValue(CHAR_FILE);
            test = line.getOptionValue(CHAR_TESTNAME);
            
            if (ip == null) ip = "0.0.0.0";
            if (port == null) port = "53";
            
            if (file != null && test != null) {
                
                InputStream is = new FileInputStream(file);
                
                if (is != null) {
                    Reader br = new BufferedReader(new InputStreamReader(is));
                    YAMLFactory fact = new DefaultYAMLFactory();
                    
                    Constructor ctor = fact.createConstructor(fact.createComposer(fact.createParser(fact.createScanner(br)),fact.createResolver()));
                    boolean found = false;
                    HashMap testMap = null;
                    while(ctor.checkData() && !found) {
                        Object o = ctor.getData();
                        if (o instanceof HashMap) {
                          testMap = (HashMap) o;
                          if (test.equals(testMap.get("description"))) {
                              found = true;
                          }
                        }
                    }
                    if (found) {
                        HashMap loadedZoneData = (HashMap) testMap.get("zonedata");
                        HashMap zonedata = new HashMap();
                        Set keys = loadedZoneData.keySet();
                        for (Iterator i = keys.iterator(); i.hasNext(); ) {
                            String hostname = (String) i.next();
                            String lowercase = hostname.toLowerCase(Locale.US);
                            zonedata.put(lowercase, loadedZoneData.get(hostname));
                        }
                        
                        DNSTestingServer testingServer = new DNSTestingServer(ip, port);
                        testingServer.setData(zonedata);
                        
                        System.out.println("Listening on "+ip+":"+port);
                        
                        while (true) {
                            try {
                                Thread.sleep(1000);
                            } catch (InterruptedException e) {
                                // TODO Auto-generated catch block
                            }
                        }
                        
                    } else {
                        throw new RuntimeException("Unable to find a <"+test+"> section in the passed file.");
                    }
                } else {
                    throw new RuntimeException("Unable to load the file: "+file);
                }

                
            } else {
                System.out.println("Missing required parameter.");
                usage();
            }
        } catch (ParseException e) {
            usage();
        } catch (RuntimeException e) {
            System.out.println("Error: "+e.getMessage());
            e.printStackTrace();
            usage();
        } catch (TextParseException e) {
            System.out.println("Parsing Error: "+e.getMessage());
            e.printStackTrace();
            usage();
        } catch (IOException e) {
            System.out.println("IO Error: "+e.getMessage());
            e.printStackTrace();
            usage();
        }

    }

    /**
     * Print out the usage
     */
    private static void usage() {
        HelpFormatter hf = new HelpFormatter();
        hf.printHelp("DNSTestingServerLauncher", generateOptions(), true);
        System.exit(0);
    }

    /**
     * Return the generated Options
     * 
     * @return options
     */
    private static Options generateOptions() {
        Options options = new Options();
        options.addOption(OptionBuilder
                .withLongOpt(CMD_IP)
                .withValueSeparator('=')
                .hasArg()
                .withArgName("ip")
                .withDescription("Listening IP (default: 0.0.0.0 for every IP)")
                .create(CHAR_IP));
        options.addOption(OptionBuilder
                .withLongOpt(CMD_PORT)
                .withValueSeparator('=')
                .hasArg()
                .withArgName("port")
                .withDescription("Listening port (default: 53)")
                .create(CHAR_PORT));
        options.addOption(OptionBuilder
                .withLongOpt(CMD_FILE)
                .withValueSeparator('=')
                .withDescription("YML file name")
                .withArgName("file")
                .isRequired()
                .hasArg()
                .create(CHAR_FILE));
        options.addOption(OptionBuilder
                .withLongOpt(CMD_TESTNAME)
                .withValueSeparator('=')
                .hasArg()
                .withDescription("Test name")
                .withArgName("test")
                .isRequired()
                .create(CHAR_TESTNAME));
        return options;
    }

}
