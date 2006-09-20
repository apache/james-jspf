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

/**
 * Logger sending everything to the standard output streams.
 * This is mainly for the cases when you have a utility that
 * does not have a logger to supply.
 */
public final class ConsoleLogger
    implements Logger
{
    /** Typecode for debugging messages. */
    public static final int LEVEL_DEBUG = 0;

    /** Typecode for informational messages. */
    public static final int LEVEL_INFO = 1;

    /** Typecode for warning messages. */
    public static final int LEVEL_WARN = 2;

    /** Typecode for error messages. */
    public static final int LEVEL_ERROR = 3;

    /** Typecode for fatal error messages. */
    public static final int LEVEL_FATAL = 4;

    /** Typecode for disabled log levels. */
    public static final int LEVEL_DISABLED = 5;

    private final int m_logLevel;

    /**
     * Creates a new ConsoleLogger with the priority set to DEBUG.
     */
    public ConsoleLogger()
    {
        this( LEVEL_DEBUG );
    }

    /**
     * Creates a new ConsoleLogger.
     * @param logLevel log level typecode
     */
    public ConsoleLogger( final int logLevel )
    {
        m_logLevel = logLevel;
    }

    /**
     * Logs a debugging message.
     *
     * @param message a <code>String</code> value
     */
    public void debug( final String message )
    {
        debug( message, null );
    }

    /**
     * Logs a debugging message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public void debug( final String message, final Throwable throwable )
    {
        if( m_logLevel <= LEVEL_DEBUG )
        {
            System.out.print( "[DEBUG] " );
            System.out.println( message );

            if( null != throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if debug-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if debug-level logging
     */
    public boolean isDebugEnabled()
    {
        return m_logLevel <= LEVEL_DEBUG;
    }

    /**
     * Logs an informational message.
     *
     * @param message a <code>String</code> value
     */
    public void info( final String message )
    {
        info( message, null );
    }

    /**
     * Logs an informational message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public void info( final String message, final Throwable throwable )
    {
        if( m_logLevel <= LEVEL_INFO )
        {
            System.out.print( "[INFO] " );
            System.out.println( message );

            if( null != throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if info-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if info-level logging is enabled
     */
    public boolean isInfoEnabled()
    {
        return m_logLevel <= LEVEL_INFO;
    }

    /**
     * Logs a warning message.
     *
     * @param message a <code>String</code> value
     */
    public void warn( final String message )
    {
        warn( message, null );
    }

    /**
     * Logs a warning message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public void warn( final String message, final Throwable throwable )
    {
        if( m_logLevel <= LEVEL_WARN )
        {
            System.out.print( "[WARNING] " );
            System.out.println( message );

            if( null != throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if warn-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if warn-level logging is enabled
     */
    public boolean isWarnEnabled()
    {
        return m_logLevel <= LEVEL_WARN;
    }

    /**
     * Logs an error message.
     *
     * @param message a <code>String</code> value
     */
    public void error( final String message )
    {
        error( message, null );
    }

    /**
     * Logs an error message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public void error( final String message, final Throwable throwable )
    {
        if( m_logLevel <= LEVEL_ERROR )
        {
            System.out.print( "[ERROR] " );
            System.out.println( message );

            if( null != throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if error-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if error-level logging is enabled
     */
    public boolean isErrorEnabled()
    {
        return m_logLevel <= LEVEL_ERROR;
    }

    /**
     * Logs a fatal error message.
     *
     * @param message a <code>String</code> value
     */
    public void fatalError( final String message )
    {
        fatalError( message, null );
    }

    /**
     * Logs a fatal error message and an exception.
     *
     * @param message a <code>String</code> value
     * @param throwable a <code>Throwable</code> value
     */
    public void fatalError( final String message, final Throwable throwable )
    {
        if( m_logLevel <= LEVEL_FATAL )
        {
            System.out.print( "[FATAL ERROR] " );
            System.out.println( message );

            if( null != throwable )
            {
                throwable.printStackTrace( System.out );
            }
        }
    }

    /**
     * Returns <code>true</code> if fatal-level logging is enabled, false otherwise.
     *
     * @return <code>true</code> if fatal-level logging is enabled
     */
    public boolean isFatalErrorEnabled()
    {
        return m_logLevel <= LEVEL_FATAL;
    }

    /**
     * Just returns this logger (<code>ConsoleLogger</code> is not hierarchical).
     *
     * @param name ignored
     * @return this logger
     */
    public Logger getChildLogger( final String name )
    {
        return this;
    }
}