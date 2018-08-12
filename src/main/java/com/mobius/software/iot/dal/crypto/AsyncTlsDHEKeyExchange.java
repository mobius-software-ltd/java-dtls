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

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.DigitallySigned;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsDHUtils;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsSigner;
import org.bouncycastle.crypto.tls.TlsUtils;

public class AsyncTlsDHEKeyExchange extends TlsDHEKeyExchange 
{
	@SuppressWarnings("rawtypes")
	public AsyncTlsDHEKeyExchange(int keyExchange,Vector supportedSignatureAlgorithms, DHParameters dhParameters) 
	{
		super(keyExchange, supportedSignatureAlgorithms, dhParameters);
	}

	public byte[] generateServerKeyExchange() throws IOException
	{
		if (this.dhParameters == null)
			throw new TlsFatalAlert(AlertDescription.internal_error);
	        
		DigestInputBuffer buf = new DigestInputBuffer();

		this.dhAgreePrivateKey = TlsDHUtils.generateEphemeralServerKeyExchange(context.getSecureRandom(),this.dhParameters, buf);
		SignatureAndHashAlgorithm signatureAndHashAlgorithm = TlsUtils.getSignatureAndHashAlgorithm(context, serverCredentials);
		Digest d = TlsUtils.createHash(signatureAndHashAlgorithm);

		SecurityParameters securityParameters = context.getSecurityParameters();
		d.update(securityParameters.getClientRandom(), 0, securityParameters.getClientRandom().length);
		d.update(securityParameters.getServerRandom(), 0, securityParameters.getServerRandom().length);
	    buf.updateDigest(d);

	    byte[] hash = new byte[d.getDigestSize()];
	    d.doFinal(hash, 0);

	    byte[] signature = serverCredentials.generateCertificateSignature(hash);

	    DigitallySigned signed_params = new DigitallySigned(signatureAndHashAlgorithm, signature);
	    signed_params.encode(buf);

	    return buf.toByteArray();
	}
	
	protected Signer initVerifyer(TlsSigner tlsSigner, SignatureAndHashAlgorithm algorithm, SecurityParameters securityParameters)
    {
        Signer signer = tlsSigner.createVerifyer(algorithm, this.serverPublicKey);
        signer.update(securityParameters.getClientRandom(), 0, securityParameters.getClientRandom().length);
        signer.update(securityParameters.getServerRandom(), 0, securityParameters.getServerRandom().length);
        return signer;
    }
}