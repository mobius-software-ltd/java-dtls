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

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.TlsServerContext;
import org.bouncycastle.crypto.tls.TlsSession;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.util.Times;

public class AsyncDtlsServerContext implements TlsServerContext 
{
	private RandomGenerator nonceRandom;
	private SecureRandom secureRandom;
	private AsyncDtlsSecurityParameters securityParameters;

	private ProtocolVersion clientVersion = null;
	private ProtocolVersion serverVersion = null;
	private TlsSession session = null;
	private Object userObject = null;
	    
	private static long counter = Times.nanoTime();

	public AsyncDtlsServerContext(SecureRandom secureRandom, AsyncDtlsSecurityParameters securityParameters)
    {
		Digest d = TlsUtils.createHash(HashAlgorithm.sha256);
        byte[] seed = new byte[d.getDigestSize()];
        secureRandom.nextBytes(seed);

        this.nonceRandom = new DigestRandomGenerator(d);
        nonceRandom.addSeedMaterial(nextCounterValue());
        nonceRandom.addSeedMaterial(Times.nanoTime());
        nonceRandom.addSeedMaterial(seed);

        this.secureRandom = secureRandom;
        this.securityParameters = securityParameters;
    }

    private synchronized static long nextCounterValue()
    {
        return ++counter;
    }
    
    public boolean isServer()
    {
        return true;
    }

	@Override
	public RandomGenerator getNonceRandomGenerator() 
	{
		return nonceRandom;
	}

	@Override
	public SecureRandom getSecureRandom() 
	{
		return secureRandom;
	}

	@Override
	public AsyncDtlsSecurityParameters getSecurityParameters() 
	{
		return securityParameters;
	}

	@Override
	public ProtocolVersion getClientVersion() 
	{
		return clientVersion;
	}

	public void setClientVersion(ProtocolVersion clientVersion)
	{
		this.clientVersion = clientVersion;
	}
	
	@Override
	public ProtocolVersion getServerVersion() 
	{
		return serverVersion;
	}

	public void setServerVersion(ProtocolVersion serverVersion)
	{
		this.serverVersion = serverVersion;
	}
	
	@Override
	public TlsSession getResumableSession() 
	{
		return session;
	}

	@Override
	public Object getUserObject() 
	{
		return userObject;
	}

	@Override
	public void setUserObject(Object userObject) 
	{
		this.userObject=userObject;
	}

	@Override
	public byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length) 
	{
		if (context_value != null && !TlsUtils.isValidUint16(context_value.length))
            throw new IllegalArgumentException("'context_value' must have length less than 2^16 (or be null)");
        
        SecurityParameters sp = getSecurityParameters();
        byte[] cr = sp.getClientRandom(), sr = sp.getServerRandom();

        int seedLength = cr.length + sr.length;
        if (context_value != null)
            seedLength += (2 + context_value.length);
        
        byte[] seed = new byte[seedLength];
        int seedPos = 0;

        System.arraycopy(cr, 0, seed, seedPos, cr.length);
        seedPos += cr.length;
        System.arraycopy(sr, 0, seed, seedPos, sr.length);
        seedPos += sr.length;
        if (context_value != null)
        {
            TlsUtils.writeUint16(context_value.length, seed, seedPos);
            seedPos += 2;
            System.arraycopy(context_value, 0, seed, seedPos, context_value.length);
            seedPos += context_value.length;
        }

        if (seedPos != seedLength)
        {
            throw new IllegalStateException("error in calculation of seed for export");
        }

        return TlsUtils.PRF(this, sp.getMasterSecret(), asciiLabel, seed, length);
	}
}
