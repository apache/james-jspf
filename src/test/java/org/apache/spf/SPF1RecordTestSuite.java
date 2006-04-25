package org.apache.spf;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.regex.Pattern;

import junit.framework.TestCase;
import junit.framework.TestSuite;

public class SPF1RecordTestSuite extends TestSuite {

    private static class SPF1RecordTest extends TestCase {
        private String recIn;

        private String errMsg;

        private String recOutAuto;

        private String recOut;
        
        public SPF1RecordTest(String command) {
            super(command);
            
            
            
        }

        public SPF1RecordTest(String command, String recIn, String errMsg,
                String recOut, String recOutAuto) {
            super(command);
            this.recIn = recIn;
            if (errMsg != null && errMsg.equals("no errors")) {
                this.errMsg = null;
            } else {
                this.errMsg = errMsg;
            }
            this.recOut = recOut;
            this.recOutAuto = recOutAuto;
        }

        protected void runTest() throws Throwable {
            String mailFrom = "byteaction.de";
            String ipAddress = "192.168.0.100";
            String helo = "byteaction.de";
            
        	try {
        		SPF1Data d = new SPF1Data(mailFrom,helo,ipAddress);
                SPF1Record r = new SPF1Record(recIn, d);
                
                r.runCheck();
                
                System.err.println("NO Exception: " + recIn + " => " + errMsg
                        + " ===> " + r.getExplanation());
                assertNull("Expected Error " + errMsg, errMsg);
                
            } catch (NoneException e) {
            	 assertEquals(errMsg, e.getMessage());
            } catch (UnknownException e) {
           	 assertEquals(errMsg, e.getMessage());
           
            } catch (NeutralException e) {
                assertEquals(errMsg, e.getMessage());;
            } catch (ErrorException e) {
                assertEquals(errMsg, e.getMessage());;
            }

        }
    }

    public SPF1RecordTestSuite() throws IOException {
        super();

        BufferedReader br = new BufferedReader(new InputStreamReader(getClass()
                .getResourceAsStream("test_parser.txt")));

        String line;

        Pattern p = Pattern.compile("[ ]+");

        String command = null;
        String recIn = null;
        String errMsg = null;
        String recOut = null;
        String recOutAuto = null;

        while ((line = br.readLine()) != null) {
            // skip comments and empty lines
            if (line.length() != 0 && line.charAt(0) != '#') {
                String[] tokens = p.split(line, 3);

                
                	
                	if (tokens.length >= 2) {

                    if ("spftest".equals(tokens[0])) {
                        if (command != null) {
                            addTest(command, recIn, errMsg, recOut, recOutAuto);
                            command = null;
                            recIn = null;
                            errMsg = null;
                            recOut = null;
                            recOutAuto = null;
                        }
                        command = tokens[2];
                    } else if ("rec-in".equals(tokens[0])) {
                        recIn = tokens[2].replaceFirst("SPF record in:  ", "");
                    } else if ("err-msg".equals(tokens[0])) {
                        errMsg = tokens[2];
                    } else if ("rec-out".equals(tokens[0])) {
                        recOut = tokens[2].replaceFirst("SPF record:  ", "");
                    } else if ("rec-out-auto".equals(tokens[0])) {
                        if (tokens.length == 3) {
                            recOutAuto = tokens[2];
                        } else {
                            recOutAuto = "";
                        }
                    } else {
                        System.err.println("Unknown token: " + tokens[0]);
                    }
                	

                } else {
                    throw new IllegalStateException("Bad format: " + line);
                }
            }

        }

        if (command != null) {
            addTest(command, recIn, errMsg, recOut, recOutAuto);
        }

        br.close();

    }

    private void addTest(String command, String recIn, String errMsg,
            String recOut, String recOutAuto) {
        if (command != null && recIn != null && errMsg != null
                && (recOut != null || recOutAuto != null)) {
            addTest(new SPF1RecordTest(command, recIn, errMsg, recOut,
                    recOutAuto));
        } else {
            System.err.println("Unexpected test sequence: " + command + "|"
                    + recIn + "|" + errMsg + "|" + recOut + "|" + recOutAuto);
        }
    }

    /**
     * Empty test method.
     */
    public void testPlaceholder() {
    }

}
