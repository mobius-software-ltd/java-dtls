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

import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.crypto.tls.TlsCipher;

public class AsyncDtlsEpoch 
{
	private final AsyncDtlsReplayWindow replayWindow = new AsyncDtlsReplayWindow();

    private final int epoch;
    private final TlsCipher cipher;

    private AtomicLong sequenceNumber = new AtomicLong(0L);

    public AsyncDtlsEpoch(int epoch, TlsCipher cipher)
    {
        if (epoch < 0)
        {
            throw new IllegalArgumentException("'epoch' must be >= 0");
        }
        if (cipher == null)
        {
            throw new IllegalArgumentException("'cipher' cannot be null");
        }

        this.epoch = epoch;
        this.cipher = cipher;
    }

    public long allocateSequenceNumber()
    {
        return sequenceNumber.getAndIncrement();
    }

    public TlsCipher getCipher()
    {
        return cipher;
    }

    public int getEpoch()
    {
        return epoch;
    }

    public AsyncDtlsReplayWindow getReplayWindow()
    {
        return replayWindow;
    }

    public long getSequenceNumber()
    {
        return sequenceNumber.get();
    }
}