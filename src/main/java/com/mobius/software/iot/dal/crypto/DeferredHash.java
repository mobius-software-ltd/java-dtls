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

import java.util.Enumeration;
import java.util.Hashtable;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.PRFAlgorithm;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsHandshakeHash;
import org.bouncycastle.util.Shorts;

/**
 * Buffers input until the hash algorithm is determined.
 */
class DeferredHash implements TlsHandshakeHash
{
    protected static final int BUFFERING_HASH_LIMIT = 4;

    protected TlsContext context;

    private DigestInputBuffer buf;
    private Hashtable<Short,Digest> hashes;
    private Short prfHashAlgorithm;

    DeferredHash()
    {
        this.buf = new DigestInputBuffer();
        this.hashes = new Hashtable<Short,Digest>();
        this.prfHashAlgorithm = null;
    }

    private DeferredHash(Short prfHashAlgorithm, Digest prfHash)
    {
        this.buf = null;
        this.hashes = new Hashtable<Short,Digest>();
        this.prfHashAlgorithm = prfHashAlgorithm;
        hashes.put(prfHashAlgorithm, prfHash);
    }

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public TlsHandshakeHash notifyPRFDetermined()
    {
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();
        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
        {
            CombinedHash legacyHash = new CombinedHash();
            legacyHash.init(context);
            buf.updateDigest(legacyHash);
            return legacyHash.notifyPRFDetermined();
        }

        switch (prfAlgorithm)
        {
	        case PRFAlgorithm.tls_prf_legacy:
	            throw new IllegalArgumentException("legacy PRF not a valid algorithm");
	        case PRFAlgorithm.tls_prf_sha256:
	        	this.prfHashAlgorithm = HashAlgorithm.sha256;
	        	break;
	        case PRFAlgorithm.tls_prf_sha384:
	        	this.prfHashAlgorithm = HashAlgorithm.sha384;
	        	break;
	        default:
	            throw new IllegalArgumentException("unknown PRFAlgorithm");
        }

        checkTrackingHash(prfHashAlgorithm);

        return this;
    }

    public void trackHashAlgorithm(short hashAlgorithm)
    {
        if (buf == null)
        {
            throw new IllegalStateException("Too late to track more hash algorithms");
        }

        checkTrackingHash(Shorts.valueOf(hashAlgorithm));
    }

    public void sealHashAlgorithms()
    {
        checkStopBuffering();
    }

    public TlsHandshakeHash stopTracking()
    {
        Digest prfHash = DtlsHelper.cloneHash(prfHashAlgorithm.shortValue(), (Digest)hashes.get(prfHashAlgorithm));
        if (buf != null)
            buf.updateDigest(prfHash);           
        
        DeferredHash result = new DeferredHash(prfHashAlgorithm, prfHash);
        result.init(context);
        return result;
    }

    public Digest forkPRFHash()
    {
        checkStopBuffering();

        if (buf != null)
        {
            Digest prfHash = DtlsHelper.createHash(prfHashAlgorithm.shortValue());
            buf.updateDigest(prfHash);
            return prfHash;
        }

        return DtlsHelper.cloneHash(prfHashAlgorithm.shortValue(), (Digest)hashes.get(prfHashAlgorithm));
    }

    public byte[] getFinalHash(short hashAlgorithm)
    {
        Digest d = (Digest)hashes.get(Shorts.valueOf(hashAlgorithm));
        if (d == null)
        {
            throw new IllegalStateException("HashAlgorithm." + HashAlgorithm.getText(hashAlgorithm) + " is not being tracked");
        }

        d = DtlsHelper.cloneHash(hashAlgorithm, d);
        if (buf != null)
        	buf.updateDigest(d);
        
        byte[] bs = new byte[d.getDigestSize()];
        d.doFinal(bs, 0);
        return bs;
    }

    public String getAlgorithmName()
    {
        throw new IllegalStateException("Use fork() to get a definite Digest");
    }

    public int getDigestSize()
    {
        throw new IllegalStateException("Use fork() to get a definite Digest");
    }

    public void update(byte input)
    {
    	if (buf != null)
        {
            buf.write(input);
            return;
        }

        Enumeration<Digest> e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = e.nextElement();
            hash.update(input);
        }
    }

    public void update(byte[] input, int inOff, int len)
    {
    	if (buf != null)
        {
    		buf.write(input, inOff, len);
            return;
        }

        Enumeration<Digest> e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            hash.update(input, inOff, len);
        }
    }

    public int doFinal(byte[] output, int outOff)
    {
        throw new IllegalStateException("Use fork() to get a definite Digest");
    }

    public void reset()
    {
        if (buf != null)
        {
            buf.reset();
            return;
        }

        Enumeration<Digest> e = hashes.elements();
        while (e.hasMoreElements())
        {
            Digest hash = (Digest)e.nextElement();
            hash.reset();
        }
    }

    protected void checkStopBuffering()
    {
        if (buf != null && hashes.size() <= BUFFERING_HASH_LIMIT)
        {
            Enumeration<Digest> e = hashes.elements();
            while (e.hasMoreElements())
            {
                Digest hash = (Digest)e.nextElement();
                buf.updateDigest(hash);
            }

            this.buf = null;
        }
    }

    protected void checkTrackingHash(Short hashAlgorithm)
    {
        if (!hashes.containsKey(hashAlgorithm))
        {
            Digest hash = DtlsHelper.createHash(hashAlgorithm.shortValue());
            hashes.put(hashAlgorithm, hash);
        }
    }
}
