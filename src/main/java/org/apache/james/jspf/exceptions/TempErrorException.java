/***********************************************************************
 * Copyright (c) 2006 The Apache Software Foundation.             *
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

package org.apache.james.jspf.exceptions;

/**
 * This exception get thrown if the result should be TempError
 * 
 * @author Norman Maurer <nm@byteaction.de>
 * @author Stefano Bagnara <apache@bago.org>
 */
public class TempErrorException extends Exception {

    private static final long serialVersionUID = 1L;

    public TempErrorException() {
        super();
    }

    public TempErrorException(String strErrorMessage) {
        super(strErrorMessage);
    }

}