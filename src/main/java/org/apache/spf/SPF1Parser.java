/***********************************************************************
 * Copyright (c) 1999-2006 The Apache Software Foundation.             *
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


package org.apache.spf;

public class SPF1Parser {

    private String parsedRecord = null;
    
    /**
     * Regex based on http://ftp.rfc-editor.org/in-notes/authors/rfc4408.txt. This will be the next official SPF-Spec
     */
    private final String ALPHA_DIGIT_REGEX = "[a-zA-Z0-9]";
    private final String MACRO_LETTER_REGEX = "[lsoditpvhcrLSODITPVHCR]";
    private final String TRANSFORMERS_REGEX = "\\d*r?";
    private final String DELEMITER_REGEX = "[\\.\\-\\+,/_\\=]";
    private final String MACRO_EXPAND_REGEX = "[(\\%\\{" + MACRO_LETTER_REGEX + TRANSFORMERS_REGEX + DELEMITER_REGEX + "*\\})(\\%\\%)(\\%\\_)(\\%\\-)]";
    private final String MACRO_LITERAL_REGEX = ""; // TODO: Check what that means
    private final String MACRO_STRING_REGEX = "[(" + MACRO_EXPAND_REGEX +")(" + MACRO_LITERAL_REGEX +")]" ;
    private final String TOP_LABEL_REGEX = "[(" + ALPHA_DIGIT_REGEX +"*" +"[a-zA-Z]{1}\\.?)(" + ALPHA_DIGIT_REGEX +"+\\-" + "[" + ALPHA_DIGIT_REGEX +"\\-]" + ALPHA_DIGIT_REGEX + ")]";
    private final String DOMAIN_END_REGEX = "[(\\." + TOP_LABEL_REGEX +"\\.*)(" + MACRO_EXPAND_REGEX + ")]";
    private final String DOMAIN_SPEC_REGEX = MACRO_STRING_REGEX + DOMAIN_END_REGEX;
    
    
    
    
    public SPF1Parser(String spfRecord,SPF1Data spfData) throws ErrorException, NoneException {
        
        String [] recordParts = spfRecord.split(" ");
        
        // if the record contains no valid spfrecord we will not continue 
        //and throw an NoneException
        if (!isValidSPFVersion(spfRecord)) {
            throw new NoneException("No valid SPF Record");
        }
        
    }
    
    /**
     * Check if the SPFRecord starts with valid version
     * @param record The Record to check
     * @return true or false
     */
    private boolean isValidSPFVersion (String record) {
        if (record.startsWith(SPF1Utils.SPF_VERSION + " ")){
            return true;
        }
        return false;
    }
    
    /**
     * Return the parsed record.
     * @return
     */
    public String getParsedRecord() {
        return parsedRecord;
    }
}
