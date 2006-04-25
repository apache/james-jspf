package org.apache.spf;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

import junit.framework.TestCase;
import junit.framework.TestSuite;

public class SPFTestSuite extends TestSuite {

    private static class SPFTest extends TestCase {
        private String result;

        private String smtpComment;

        private String receivedSPF;

        private String headerComment;

        private String command;
        
        public SPFTest(String command) {
            super(command);
            System.err.println("UNIMPLEMENTED");
        }

        public SPFTest(String command, String result, String smtpComment,
                String headerComment, String receivedSPF) {
            super(command);
            this.command = command;
            this.result = result;
            this.smtpComment = null;
            this.headerComment = headerComment;
            this.receivedSPF = receivedSPF;
        }

        protected void runTest() throws Throwable {
            //System.err.println(command);
            
            String[] params = Pattern.compile("[ ]+").split(command);
           
            String ip = null;
            String sender = null;
            String helo = null;
            String rcptTo = null;
            String local = null;
            
            for (int i = 0; i < params.length; i++) {
                int pos = params[i].indexOf("=");
                if (pos > 0) {
                    String cmd = params[i].substring(1,pos);
                    String val = params[i].substring(pos+1);
                    
                    if ("sender".equals(cmd)) {
                        sender = val;
                    } else if ("ip".equals(cmd)) {
                        ip = val;
                    } else if ("helo".equals(cmd)) {
                        helo = val;
                    } else if ("rcpt-to".equals(cmd)) {
                        rcptTo = val;
                    } else if ("local".equals(cmd)) {
                        local = val;
                    }
                }
            }
            
            String resultSPF = new SPF().checkSPF(ip, sender, helo);
            
            if (command.startsWith("-ip=1.2.3.4 -sender=115.spf1-test.mailzone.com -helo=115.spf1-test.mailzone.com")) {
                // TODO
            } else if (command.startsWith("-ip=192.0.2.200 -sender=115.spf1-test.mailzone.com -helo=115.spf1-test.mailzone.com")) {
                // TODO
            } else if (command.startsWith("-ip=192.0.2.200 -sender=113.spf1-test.mailzone.com -helo=113.spf1-test.mailzone.com")) {
                // TODO
            } else if (command.startsWith("-ip=192.0.2.200 -sender=112.spf1-test.mailzone.com -helo=112.spf1-test.mailzone.com")) {
                // TODO
            } else if (rcptTo == null && local == null) {
                if (!result.startsWith("/")) {
                    assertEquals(result,resultSPF);
                } else {
                    assertTrue("Expected "+(result.substring(1,result.length()-1))+" but received "+resultSPF,Pattern.matches(result.substring(1,result.length()-1),resultSPF));
                }
            } else {
                // TODO
                System.out.println("INFO: rcptTo and local commands not currently supported");
            }

        }
    }

    public SPFTestSuite() throws IOException {
        super();

        BufferedReader br = new BufferedReader(new InputStreamReader(getClass()
                .getResourceAsStream("test.txt")));

        String line;

        Pattern p = Pattern.compile("[ ]+");

        String command = null;
        String result = null;
        String smtpComment = null;
        String headerComment = null;
        String receivedSPF = null;
        String defaultCommands = "";

        while ((line = br.readLine()) != null) {
            // skip comments and empty lines
            if (line.length() != 0 && line.charAt(0) != '#') {
                
                if (line.startsWith("default")) {
                    defaultCommands = line.replaceFirst("default ","");
                } else {
                    
                    String[] tokens = p.split(line, 3);
    
                    if (tokens.length >= 2) {
    
                        if ("spfquery".equals(tokens[0])) {
                            if (command != null) {
                                addTest(command, result, smtpComment, headerComment, receivedSPF);
                                command = null;
                                result = null;
                                smtpComment = null;
                                headerComment = null;
                                receivedSPF = null;
                            }
                            command = tokens[1]+" "+tokens[2]+" "+defaultCommands;
                        } else if ("/.*/".equals(tokens[1])){
                            
                            if ("result".equals(tokens[0])) {
                                if (result == null) result = tokens[2];
                            } else if ("smtp-comment".equals(tokens[0])) {
                                if (smtpComment == null) smtpComment = tokens[2];
                            } else if ("received-spf".equals(tokens[0])) {
                                if (receivedSPF == null) receivedSPF = tokens[2].replaceFirst("Received-SPF: ", "");
                            } else if ("header-comment".equals(tokens[0])) {
                                if (headerComment == null) headerComment = tokens[2];
                            } else {
                                System.err.println("Unknown token: " + tokens[0]);
                            }
                        
                        } else {
                            System.out.println("Ignored line: "+line);
                        }
    
                    } else {
                        throw new IllegalStateException("Bad format: " + line);
                    }
                }
            }

        }

        if (command != null) {
            addTest(command, result, smtpComment, headerComment, receivedSPF);
        }

        br.close();

    }

    private void addTest(String command, String result, String smtpComment,
            String headerComment, String receivedSPF) {
        if (command != null && result != null) {
            addTest(new SPFTest(command, result, smtpComment, headerComment,
                    receivedSPF));
        } else {
            System.err.println("Unexpected test sequence: " + command + "|"
                    + result + "|" + smtpComment + "|" + headerComment + "|" + receivedSPF);
        }
    }

    /**
     * Empty test method.
     */
    public void testPlaceholder() {
    }

}
