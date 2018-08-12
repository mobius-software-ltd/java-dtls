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
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Vector;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.DigitallySigned;
import org.bouncycastle.crypto.tls.NamedCurve;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsECCUtils;
import org.bouncycastle.crypto.tls.TlsECDHEKeyExchange;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsSigner;
import org.bouncycastle.crypto.tls.TlsUtils;
import org.bouncycastle.util.Arrays;

public class AsyncTlsECDHEKeyExchange extends TlsECDHEKeyExchange
{
	@SuppressWarnings("rawtypes")
	public AsyncTlsECDHEKeyExchange(int keyExchange,Vector supportedSignatureAlgorithms, int[] namedCurves,short[] clientECPointFormats, short[] serverECPointFormats) 
	{
		super(keyExchange, supportedSignatureAlgorithms, namedCurves,clientECPointFormats, serverECPointFormats);
	}	
	
	public byte[] generateServerKeyExchange() throws IOException
	{
		DigestInputBuffer buf = new DigestInputBuffer();

		this.ecAgreePrivateKey = generateEphemeralServerKeyExchange(context.getSecureRandom(), namedCurves, clientECPointFormats, buf);
	        
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
	 
	private ECPrivateKeyParameters generateEphemeralServerKeyExchange(SecureRandom random, int[] namedCurves, short[] ecPointFormats, OutputStream output) throws IOException
	{
		int namedCurve = -1;
		if (namedCurves == null)
			namedCurve = NamedCurve.secp256r1;
		else
			for (int i = 0; i < namedCurves.length; ++i)
			{
				int entry = namedCurves[i];
				if (NamedCurve.isValid(entry) && TlsECCUtils.isSupportedNamedCurve(entry))
				{
					namedCurve = entry;
					break;
				}
			}
	        
		ECDomainParameters ecParams = null;
	    if (namedCurve >= 0)
	    	ecParams = TlsECCUtils.getParametersForNamedCurve(namedCurve);
	    else
	    {
	    	if (Arrays.contains(namedCurves, NamedCurve.arbitrary_explicit_prime_curves))
	    		ecParams = TlsECCUtils.getParametersForNamedCurve(NamedCurve.secp256r1);
	    	else if (Arrays.contains(namedCurves, NamedCurve.arbitrary_explicit_char2_curves))
	    		ecParams = TlsECCUtils.getParametersForNamedCurve(NamedCurve.sect283r1);	           
	    }

	    if (ecParams == null)
	    	throw new TlsFatalAlert(AlertDescription.internal_error);
	        
	    if (namedCurve < 0)
	    	TlsECCUtils.writeExplicitECParameters(ecPointFormats, ecParams, output);
	    else
	    	TlsECCUtils.writeNamedECParameters(namedCurve, output);
	        
	    return TlsECCUtils.generateEphemeralClientKeyExchange(random, ecPointFormats, ecParams, output);
	}
}