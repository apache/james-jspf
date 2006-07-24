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

import org.apache.james.jspf.core.Logger;
import org.apache.log4j.Level;

/**
 * Implementation of the Logger interface using the Log4J implementation
 * strategy.
 */
public class Log4JLogger implements Logger {
    private org.apache.log4j.Logger m_Logger;

    Log4JLogger(org.apache.log4j.Logger log4jLogger) {
        m_Logger = log4jLogger;
    }

    /**
     * Log a debug message.
     * 
     * @param message
     *            the message
     */
    public void debug(String message) {
        m_Logger.debug(message);
    }

    /**
     * Log a debug message.
     * 
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public void debug(String message, Throwable throwable) {
        m_Logger.debug(message, throwable);
    }

    /**
     * Determine if messages of priority "debug" will be logged.
     * 
     * @return true if "debug" messages will be logged
     */
    public boolean isDebugEnabled() {
        return m_Logger.isDebugEnabled();
    }

    /**
     * Log a info message.
     * 
     * @param message
     *            the message
     */
    public void info(String message) {
        m_Logger.info(message);
    }

    /**
     * Log a info message.
     * 
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public void info(String message, Throwable throwable) {
        m_Logger.info(message, throwable);
    }

    /**
     * Determine if messages of priority "info" will be logged.
     * 
     * @return true if "info" messages will be logged
     */
    public boolean isInfoEnabled() {
        return m_Logger.isInfoEnabled();
    }

    /**
     * Log a warn message.
     * 
     * @param message
     *            the message
     */
    public void warn(String message) {
        m_Logger.warn(message);
    }

    /**
     * Log a warn message.
     * 
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public void warn(String message, Throwable throwable) {
        m_Logger.warn(message, throwable);
    }

    /**
     * Determine if messages of priority "warn" will be logged.
     * 
     * @return true if "warn" messages will be logged
     */
    public boolean isWarnEnabled() {
        return m_Logger.isEnabledFor(Level.WARN);
    }

    /**
     * Log a error message.
     * 
     * @param message
     *            the message
     */
    public void error(String message) {
        m_Logger.error(message);
    }

    /**
     * Log a error message.
     * 
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public void error(String message, Throwable throwable) {
        m_Logger.error(message, throwable);
    }

    /**
     * Determine if messages of priority "error" will be logged.
     * 
     * @return true if "error" messages will be logged
     */
    public boolean isErrorEnabled() {
        return m_Logger.isEnabledFor(Level.ERROR);
    }

    /**
     * Log a fatalError message.
     * 
     * @param message
     *            the message
     */
    public void fatalError(String message) {
        m_Logger.fatal(message);
    }

    /**
     * Log a fatalError message.
     * 
     * @param message
     *            the message
     * @param throwable
     *            the throwable
     */
    public void fatalError(String message, Throwable throwable) {
        m_Logger.fatal(message, throwable);
    }

    /**
     * Determine if messages of priority "fatalError" will be logged.
     * 
     * @return true if "fatalError" messages will be logged
     */
    public boolean isFatalErrorEnabled() {
        return m_Logger.isEnabledFor(Level.FATAL);
    }

    /**
     * Create a new child logger. The name of the child logger is
     * [current-loggers-name].[passed-in-name] Throws
     * <code>IllegalArgumentException</code> if name has an empty element name
     * 
     * @param name
     *            the subname of this logger
     * @return the new logger
     */
    public Logger getChildLogger(String name) {
        String newName = m_Logger.getName() + "." + name;
        org.apache.log4j.Logger childLog4JLogger = org.apache.log4j.Logger
                .getLogger(newName);
        Log4JLogger child = new Log4JLogger(childLog4JLogger);
        return child;
    }
}
