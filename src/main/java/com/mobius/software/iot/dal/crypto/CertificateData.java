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
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.DefaultTlsAgreementCredentials;
import org.bouncycastle.crypto.tls.DefaultTlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsAgreementCredentials;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

public class CertificateData 
{
	private X509Certificate certificate;
	private PrivateKey privateKey;
	private AsymmetricKeyParameter keyParameter;
	private Certificate chain;
	private TlsAgreementCredentials agreementCredentials;
	private TlsEncryptionCredentials encryptionCredentials;
	private TlsContext tlsContext;
	
	public CertificateData(KeyStore keystore,String keystorePassword,TlsContext tlsContext,Boolean isClient,String certificateAlias) throws KeyStoreException,UnrecoverableKeyException,NoSuchAlgorithmException,CertificateEncodingException,IOException
	{
		this.tlsContext=tlsContext;
		List<X509Certificate> allCertificates=new ArrayList<X509Certificate>();
		
		if(keystore!=null)
		{	
			Enumeration<String> aliasesEnum = keystore.aliases();
			while(aliasesEnum.hasMoreElements())
			{
				String alias=aliasesEnum.nextElement();
				X509Certificate currCertificate = (X509Certificate) keystore.getCertificate(alias);
				PrivateKey currKey=null;
				if(certificateAlias==null || certificateAlias.equals(alias))
					currKey=(PrivateKey) keystore.getKey(alias, keystorePassword.toCharArray());				
				
				if(currKey!=null)
				{
					privateKey=currKey;
					certificate=currCertificate;
					keyParameter = PrivateKeyFactory.createKey(privateKey.getEncoded());
				}
				
				if(currCertificate!=null)
				{
					if(currKey!=null)
						allCertificates.add(0, currCertificate);
					else
						allCertificates.add(currCertificate);
				}
			}
		}
		
		if(!isClient && privateKey==null)
			throw new KeyStoreException("No private key found");
		
		if(!isClient && allCertificates.size()==0)
			throw new KeyStoreException("No certificate found");
		
		org.bouncycastle.asn1.x509.Certificate[] certificateChain = new org.bouncycastle.asn1.x509.Certificate[allCertificates.size()];
        for (int i = 0; i < allCertificates.size(); ++i) {
        	certificateChain[i] = org.bouncycastle.asn1.x509.Certificate.getInstance(allCertificates.get(i).getEncoded());
        }
        
        chain=new Certificate(certificateChain);
        if(!chain.isEmpty())
        {
        	if(keyParameter!=null)
        		encryptionCredentials = new DefaultTlsEncryptionCredentials(tlsContext, chain, keyParameter);
        	
        	try
        	{
        		agreementCredentials = new DefaultTlsAgreementCredentials(chain, keyParameter);
        	}
        	catch(Exception ex)
        	{
        		//may be invalid key format
        	}
        }
	}

	public X509Certificate getCertificate() 
	{
		return certificate;
	}

	public PrivateKey getPrivateKey() 
	{
		return privateKey;
	}

	public AsymmetricKeyParameter getKeyParameter() 
	{
		return keyParameter;
	}

	public Certificate getChain() 
	{
		return chain;
	}

	public TlsAgreementCredentials getAgreementCredentials() 
	{
		return agreementCredentials;
	}

	public TlsEncryptionCredentials getEncryptionCredentials() 
	{
		return encryptionCredentials;
	}

	public TlsSignerCredentials getSignerCredentials(SignatureAndHashAlgorithm signatureAndHashAlgorithm) 
	{
		if(chain.isEmpty())
			return null;
		
		return new DefaultTlsSignerCredentials(tlsContext, chain, keyParameter, signatureAndHashAlgorithm);
	}
}