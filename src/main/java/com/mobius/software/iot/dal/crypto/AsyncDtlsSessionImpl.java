package com.mobius.software.iot.dal.crypto;

/**
 * Mobius Software LTD
 * Copyright 2018, Mobius Software LTD
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

import org.bouncycastle.crypto.tls.SessionParameters;
import org.bouncycastle.crypto.tls.TlsSession;

public class AsyncDtlsSessionImpl implements TlsSession
{
    final byte[] sessionID;
    SessionParameters sessionParameters;

    public AsyncDtlsSessionImpl(byte[] sessionID, SessionParameters sessionParameters)
    {
        if (sessionID == null)
            throw new IllegalArgumentException("'sessionID' cannot be null");
        
        if (sessionID.length < 1 || sessionID.length > 32)
            throw new IllegalArgumentException("'sessionID' must have length between 1 and 32 bytes, inclusive");
                
        this.sessionID = new byte[sessionID.length];
        System.arraycopy(sessionID, 0, this.sessionID, 0, sessionID.length);
        this.sessionParameters = sessionParameters;
    }

    public SessionParameters exportSessionParameters()
    {
        return this.sessionParameters == null ? null : this.sessionParameters.copy();
    }

    public byte[] getSessionID()
    {
        return sessionID;
    }

    public void invalidate()
    {
        if (this.sessionParameters != null)
        {
            this.sessionParameters.clear();
            this.sessionParameters = null;
        }
    }

    public boolean isResumable()
    {
        return this.sessionParameters != null;
    }
}