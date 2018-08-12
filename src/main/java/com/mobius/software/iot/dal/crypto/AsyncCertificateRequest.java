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

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.io.IOException;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.CertificateRequest;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsFatalAlert;

public class AsyncCertificateRequest extends CertificateRequest 
{

	@SuppressWarnings("rawtypes")
	public AsyncCertificateRequest(short[] certificateTypes,Vector supportedSignatureAlgorithms, Vector certificateAuthorities) 
	{
		super(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);
	}

	public ByteBuf encode(short sequence) throws IOException
	{
		int length=DtlsHelper.HANDSHAKE_MESSAGE_HEADER_LENGTH;
		if (certificateTypes == null || certificateTypes.length == 0)
			length++;
        else
        	length+=1+certificateTypes.length;
		
		if (supportedSignatureAlgorithms != null)
		{
			for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
	        {
	            SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
	            if (entry.getSignature() == SignatureAlgorithm.anonymous)
	            	 throw new IllegalArgumentException("SignatureAlgorithm.anonymous MUST NOT appear in the signature_algorithms extension");	            
	        }
			
        	length += 2*supportedSignatureAlgorithms.size() + 2;
		}		

		Vector<byte[]> derEncodings = new Vector<byte[]>(certificateAuthorities.size());
		int totalLength = 0;
        
		if (certificateAuthorities == null || certificateAuthorities.isEmpty())
        	length+=2;
        else
        {
            length+=2;
            for (int i = 0; i < certificateAuthorities.size(); ++i)
            {
                X500Name certificateAuthority = (X500Name)certificateAuthorities.elementAt(i);
                byte[] derEncoding = certificateAuthority.getEncoded(ASN1Encoding.DER);
                derEncodings.addElement(derEncoding);
                length += derEncoding.length + 2;
                totalLength+=derEncoding.length + 2;
            }
        }
		
		ByteBuf buffer=Unpooled.buffer(length);
		DtlsHelper.writeHandshakeHeader(sequence,MessageType.CERTIFICATE_REQUEST,buffer,length);
    	
		if (certificateTypes == null || certificateTypes.length == 0)
        	buffer.writeByte(0);
        else
        {
        	buffer.writeByte(certificateTypes.length);
        	for(short curr:certificateTypes)
        		buffer.writeByte(curr);        		             
        }

        if (supportedSignatureAlgorithms != null)
        {
        	buffer.writeShort(2 * supportedSignatureAlgorithms.size());
            for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
            {
                SignatureAndHashAlgorithm entry = (SignatureAndHashAlgorithm)supportedSignatureAlgorithms.elementAt(i);
                buffer.writeByte(entry.getHash());
                buffer.writeByte(entry.getSignature());                
            }
        }

        if (certificateAuthorities == null || certificateAuthorities.isEmpty())
        	buffer.writeShort(0);
        else
        {
            buffer.writeShort(totalLength);
            for (int i = 0; i < derEncodings.size(); ++i)
            {
                byte[] derEncoding = (byte[])derEncodings.elementAt(i);
                buffer.writeShort(derEncoding.length);
                buffer.writeBytes(derEncoding);
            }
        }
        
        return buffer;
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static AsyncCertificateRequest parse(ProtocolVersion version,ByteBuf data) throws IOException
	{
		 int numTypes = data.readUnsignedByte();
		 short[] certificateTypes = new short[numTypes];
		 for (int i = 0; i < numTypes; ++i)
			 certificateTypes[i] = data.readUnsignedByte();
	     
		 Vector supportedSignatureAlgorithms = null;
		 if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion()))
			 supportedSignatureAlgorithms = DtlsHelper.parseSupportedSignatureAlgorithms(false, data);
	        
		 Vector certificateAuthorities = new Vector();
		 int remainingBytes=data.readUnsignedShort();
		 while (remainingBytes>0)
		 {
			 byte[] derEncoding = new byte[data.readUnsignedShort()];
			 data.readBytes(derEncoding);
			 ASN1InputStream asn1 = new ASN1InputStream(derEncoding);
			 ASN1Primitive result = asn1.readObject();
			 asn1.close();
			 if (null == result)
				 throw new TlsFatalAlert(AlertDescription.decode_error);
		        
			 if (null != asn1.readObject())
		            throw new TlsFatalAlert(AlertDescription.decode_error);
		        
			 certificateAuthorities.addElement(X500Name.getInstance(asn1));
			 remainingBytes-=2+derEncoding.length;
		 }

		 return new AsyncCertificateRequest(certificateTypes, supportedSignatureAlgorithms, certificateAuthorities);
	}
}