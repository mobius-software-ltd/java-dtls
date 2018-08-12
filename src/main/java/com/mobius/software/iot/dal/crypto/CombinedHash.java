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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsHandshakeHash;

/**
 * A combined hash, which implements md5(m) || sha1(m).
 */
public class CombinedHash implements TlsHandshakeHash
{
    protected TlsContext context;
    protected Digest md5;
    protected Digest sha1;

    public CombinedHash()
    {
        this.md5 = DtlsHelper.createHash(HashAlgorithm.md5);
        this.sha1 = DtlsHelper.createHash(HashAlgorithm.sha1);
    }

    public CombinedHash(CombinedHash t)
    {
        this.context = t.context;
        this.md5 = DtlsHelper.cloneHash(HashAlgorithm.md5, t.md5);
        this.sha1 = DtlsHelper.cloneHash(HashAlgorithm.sha1, t.sha1);
    }

    public void init(TlsContext context)
    {
        this.context = context;
    }

    public TlsHandshakeHash notifyPRFDetermined()
    {
        return this;
    }

    public void trackHashAlgorithm(short hashAlgorithm)
    {
        throw new IllegalStateException("CombinedHash only supports calculating the legacy PRF for handshake hash");
    }

    public void sealHashAlgorithms()
    {
    }

    public TlsHandshakeHash stopTracking()
    {
        return new CombinedHash(this);
    }

    public Digest forkPRFHash()
    {
        return new CombinedHash(this);
    }

    public byte[] getFinalHash(short hashAlgorithm)
    {
        throw new IllegalStateException("CombinedHash doesn't support multiple hashes");
    }

    /**
     * @see org.bouncycastle.crypto.Digest#getAlgorithmName()
     */
    public String getAlgorithmName()
    {
        return md5.getAlgorithmName() + " and " + sha1.getAlgorithmName();
    }

    /**
     * @see org.bouncycastle.crypto.Digest#getDigestSize()
     */
    public int getDigestSize()
    {
        return md5.getDigestSize() + sha1.getDigestSize();
    }

    /**
     * @see org.bouncycastle.crypto.Digest#update(byte)
     */
    public void update(byte input)
    {
        md5.update(input);
        sha1.update(input);
    }

    /**
     * @see org.bouncycastle.crypto.Digest#update(byte[], int, int)
     */
    public void update(byte[] input, int inOff, int len)
    {
        md5.update(input, inOff, len);
        sha1.update(input, inOff, len);
    }

    /**
     * @see org.bouncycastle.crypto.Digest#doFinal(byte[], int)
     */
    public int doFinal(byte[] output, int outOff)
    {
        if (context != null && context.getServerVersion().isSSL())
        {
            ssl3Complete(md5, DtlsHelper.IPAD, DtlsHelper.OPAD, 48);
            ssl3Complete(sha1, DtlsHelper.IPAD, DtlsHelper.OPAD, 40);
        }

        int i1 = md5.doFinal(output, outOff);
        int i2 = sha1.doFinal(output, outOff + i1);
        return i1 + i2;
    }

    /**
     * @see org.bouncycastle.crypto.Digest#reset()
     */
    public void reset()
    {
        md5.reset();
        sha1.reset();
    }

    protected void ssl3Complete(Digest d, byte[] ipad, byte[] opad, int padLength)
    {
        byte[] master_secret = context.getSecurityParameters().getMasterSecret();

        d.update(master_secret, 0, master_secret.length);
        d.update(ipad, 0, padLength);

        byte[] tmp = new byte[d.getDigestSize()];
        d.doFinal(tmp, 0);

        d.update(master_secret, 0, master_secret.length);
        d.update(opad, 0, padLength);
        d.update(tmp, 0, tmp.length);
    }
}
