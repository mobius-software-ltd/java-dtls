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

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsEncryptionCredentials;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsServerContext;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.tls.TlsUtils;

public class AsyncDtlsServer extends DefaultTlsServer 
{
    private static final Logger logger = Logger.getLogger(AsyncDtlsServer.class);
    private CertificateData certificateData;
    private org.bouncycastle.crypto.tls.Certificate clientCertificate=null;
    
    private KeyStore keystore;
    private String keystorePassword;
    
    public AsyncDtlsServer(KeyStore keystore,String keystorePassword)
    {    	
    	this.keystore=keystore;
    	this.keystorePassword=keystorePassword;
    }

    public void initServer(TlsServerContext context) throws KeyStoreException,UnrecoverableKeyException,NoSuchAlgorithmException,CertificateEncodingException,IOException
    {
    	super.init(context);
    	this.certificateData=new CertificateData(keystore, keystorePassword, context, false);	
    }
    
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) 
    {
    	if(alertLevel==AlertLevel.fatal)
    		logger.error("DTLS raised error alert " + AlertDescription.getText(alertDescription),cause);
    	else
    		logger.warn("DTLS raised warning alert " + AlertDescription.getText(alertDescription));        
    }

    public void notifyAlertReceived(short alertLevel, short alertDescription) 
    {
    	if(alertLevel==AlertLevel.fatal)
    		logger.error("DTLS received error alert " + AlertDescription.getText(alertDescription));
    	else
    		logger.warn("DTLS received warning alert " + AlertDescription.getText(alertDescription)); 
    }

    public CertificateRequest getCertificateRequest() throws IOException 
    {
        Vector<SignatureAndHashAlgorithm> serverSigAlgs = null;

        if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(serverVersion)) 
        {
            short[] hashAlgorithms = new short[] { HashAlgorithm.sha512, HashAlgorithm.sha384, HashAlgorithm.sha256, HashAlgorithm.sha224, HashAlgorithm.sha1 };
            short[] signatureAlgorithms = new short[] { SignatureAlgorithm.rsa };

            serverSigAlgs = new Vector<SignatureAndHashAlgorithm>();
            for (int i = 0; i < hashAlgorithms.length; ++i) {
                for (int j = 0; j < signatureAlgorithms.length; ++j)
                    serverSigAlgs.addElement(new SignatureAndHashAlgorithm(hashAlgorithms[i], signatureAlgorithms[j]));                
            }
        }

        Vector<X500Name> certificateAuthorities = new Vector<X500Name>();
        return new CertificateRequest(new short[] { ClientCertificateType.rsa_sign }, serverSigAlgs,certificateAuthorities);
    }

    public void notifyClientCertificate(org.bouncycastle.crypto.tls.Certificate clientCertificate) throws IOException {
    	this.clientCertificate=clientCertificate;
    }

    public ProtocolVersion getMaximumVersion() 
    {
        return ProtocolVersion.DTLSv12;
    }

    public ProtocolVersion getMinimumVersion() 
    {
        return ProtocolVersion.DTLSv10;
    }

    public TlsEncryptionCredentials getRSAEncryptionCredentials() throws IOException {
        return certificateData.getEncryptionCredentials();
    }

    public TlsSignerCredentials getRSASignerCredentials() throws IOException 
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        Vector<?> sigAlgs = supportedSignatureAlgorithms;
        if (sigAlgs != null) 
        {
            for (int i = 0; i < sigAlgs.size(); ++i) 
            {
                SignatureAndHashAlgorithm sigAlg = (SignatureAndHashAlgorithm) sigAlgs.elementAt(i);
                if (sigAlg.getSignature() == SignatureAlgorithm.rsa) 
                {
                    signatureAndHashAlgorithm = sigAlg;
                    break;
                }
            }

            if (signatureAndHashAlgorithm == null)
                return null;            
        }
        
        return certificateData.getSignerCredentials(signatureAndHashAlgorithm);
    }

    public TlsSignerCredentials getDSASignerCredentials() throws IOException 
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        Vector<?> sigAlgs = supportedSignatureAlgorithms;
        if (sigAlgs != null) 
        {
            for (int i = 0; i < sigAlgs.size(); ++i) 
            {
                SignatureAndHashAlgorithm sigAlg = (SignatureAndHashAlgorithm) sigAlgs.elementAt(i);
                if (sigAlg.getSignature() == SignatureAlgorithm.dsa) 
                {
                    signatureAndHashAlgorithm = sigAlg;
                    break;
                }
            }

            if (signatureAndHashAlgorithm == null)
                return null;            
        }
        
        return certificateData.getSignerCredentials(signatureAndHashAlgorithm);
    }
    
    public TlsSignerCredentials getECDSASignerCredentials() throws IOException 
    {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
        Vector<?> sigAlgs = supportedSignatureAlgorithms;
        if (sigAlgs != null) 
        {
            for (int i = 0; i < sigAlgs.size(); ++i) 
            {
                SignatureAndHashAlgorithm sigAlg = (SignatureAndHashAlgorithm) sigAlgs.elementAt(i);
                if (sigAlg.getSignature() == SignatureAlgorithm.ecdsa) 
                {
                    signatureAndHashAlgorithm = sigAlg;
                    break;
                }
            }

            if (signatureAndHashAlgorithm == null)
                return null;            
        }
        
        return certificateData.getSignerCredentials(signatureAndHashAlgorithm);
    }
    
	public org.bouncycastle.crypto.tls.Certificate getClientCertificate() 
	{
		return clientCertificate;
	}
	
	@Override
	protected TlsKeyExchange createDHEKeyExchange(int keyExchange)
    {
        return new AsyncTlsDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, getDHParameters());
    }

	@Override
	protected TlsKeyExchange createECDHEKeyExchange(int keyExchange)
    {
        return new AsyncTlsECDHEKeyExchange(keyExchange, supportedSignatureAlgorithms, namedCurves, clientECPointFormats,serverECPointFormats);
    }
}