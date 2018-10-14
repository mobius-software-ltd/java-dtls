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
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.util.Vector;

import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsClient;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsAuthentication;
import org.bouncycastle.crypto.tls.TlsClientContext;
import org.bouncycastle.crypto.tls.TlsCredentials;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;

public class AsyncDtlsClient extends DefaultTlsClient 
{
	private CertificateData certificateData;
	private org.bouncycastle.asn1.x509.Certificate[] serverCertificates;
	
	private KeyStore keystore;
	private String keystorePassword;
	private int[] definedCipherSuities=null;
	
	public AsyncDtlsClient(KeyStore keystore,String keystorePassword,int[] definedCipherSuities)
    {
		this.keystore=keystore;
		this.keystorePassword=keystorePassword;
		this.definedCipherSuities=definedCipherSuities;
    }
    
	public void initClient(TlsClientContext context) throws KeyStoreException,UnrecoverableKeyException,NoSuchAlgorithmException,CertificateEncodingException,IOException
	{
		super.init(context);
		this.certificateData=new CertificateData(keystore, keystorePassword, context, true, null);
	}
	
    public ProtocolVersion getClientVersion() 
    {
        return ProtocolVersion.DTLSv12;
    }

    public ProtocolVersion getMinimumVersion() 
    {
        return ProtocolVersion.DTLSv10;
    }
    
    public org.bouncycastle.asn1.x509.Certificate[] getServerCertificates()
    {
    	return this.serverCertificates;
    }
    
    @Override
    public int[] getCipherSuites()
    {
    	if(definedCipherSuities!=null)
    		return definedCipherSuities;
    	
        return new int[]
        {
        	CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        	CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
            CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        };
    }
    
	@Override
	public TlsAuthentication getAuthentication() throws IOException 
	{
        return new TlsAuthentication() 
        {
            public void notifyServerCertificate(org.bouncycastle.crypto.tls.Certificate serverCertificate) throws IOException 
            {
                serverCertificates = serverCertificate.getCertificateList();
                
            }

            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException 
            {
            	if(certificateData.getCertificate()==null)
                	return null;
                
            	Vector<?> sigAlgs = certificateRequest.getSupportedSignatureAlgorithms();
                if (sigAlgs != null) 
                {
                    for (int i = 0; i < sigAlgs.size(); ++i) 
                    {
                        SignatureAndHashAlgorithm sigAlg = (SignatureAndHashAlgorithm) sigAlgs.elementAt(i);
                    	TlsSignerCredentials signer=certificateData.getSignerCredentials(sigAlg);
                    	if(signer!=null)
                        	return signer;
                    }                       
                }
                
                return null;
            }
        };
    }
	
	@Override
	protected TlsKeyExchange createDHEKeyExchange(int keyExchange)
	{
		return new AsyncTlsDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, null);
	}

	@Override
	protected TlsKeyExchange createECDHEKeyExchange(int keyExchange)
	{
		return new AsyncTlsECDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,serverECPointFormats);
	}
}