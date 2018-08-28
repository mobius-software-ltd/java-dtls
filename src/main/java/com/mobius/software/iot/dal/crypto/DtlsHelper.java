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
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CertificateStatus;
import org.bouncycastle.crypto.tls.CertificateStatusType;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.CipherType;
import org.bouncycastle.crypto.tls.ClientCertificateType;
import org.bouncycastle.crypto.tls.EncryptionAlgorithm;
import org.bouncycastle.crypto.tls.ExporterLabel;
import org.bouncycastle.crypto.tls.ExtensionType;
import org.bouncycastle.crypto.tls.HashAlgorithm;
import org.bouncycastle.crypto.tls.MaxFragmentLength;
import org.bouncycastle.crypto.tls.NewSessionTicket;
import org.bouncycastle.crypto.tls.PRFAlgorithm;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SecurityParameters;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.SupplementalDataEntry;
import org.bouncycastle.crypto.tls.TlsContext;
import org.bouncycastle.crypto.tls.TlsExtensionsUtils;
import org.bouncycastle.crypto.tls.TlsFatalAlert;
import org.bouncycastle.crypto.tls.TlsHandshakeHash;
import org.bouncycastle.crypto.tls.TlsKeyExchange;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;

public class DtlsHelper 
{
	public static final byte[] EMPTY_BYTES = new byte[0];
	public static final byte[] EMPTY_BYTES_WITH_LENGTH = new byte[] { 0x00 };
    
	public static final Integer EXT_RenegotiationInfo = ExtensionType.renegotiation_info;
	public static final Integer EXT_SessionTicket = ExtensionType.session_ticket;

	public static final Integer EXT_encrypt_then_mac = ExtensionType.encrypt_then_mac;
    public static final Integer EXT_extended_master_secret = ExtensionType.extended_master_secret;
    public static final Integer EXT_heartbeat = ExtensionType.heartbeat;
    public static final Integer EXT_max_fragment_length = ExtensionType.max_fragment_length;
    public static final Integer EXT_padding = ExtensionType.padding;
    public static final Integer EXT_server_name = ExtensionType.server_name;
    public static final Integer EXT_status_request = ExtensionType.status_request;
    public static final Integer EXT_truncated_hmac = ExtensionType.truncated_hmac;

    public final static byte IPAD_BYTE = (byte)0x36;
    public final static byte OPAD_BYTE = (byte)0x5C;

    public static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    public static final byte[] OPAD = genPad(OPAD_BYTE, 48);

    public static final Integer HANDSHAKE_MESSAGE_HEADER_LENGTH = 12;
    public static final byte[][] SSL3_CONST = genSSL3Const();

    public static byte[][] genSSL3Const()
    {
        int n = 10;
        byte[][] arr = new byte[n][];
        for (int i = 0; i < n; i++)
        {
            byte[] b = new byte[i + 1];
            Arrays.fill(b, (byte)('A' + i));
            arr[i] = b;
        }
        return arr;
    }
    
    public static short evaluateMaxFragmentLengthExtension(boolean resumedSession, Hashtable<?,?> clientExtensions,Hashtable<?,?> serverExtensions, short alertDescription) throws IOException
	{
		short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
		if (maxFragmentLength >= 0)
		{
			if (!MaxFragmentLength.isValid(maxFragmentLength) || (!resumedSession && maxFragmentLength != TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions)))
				throw new TlsFatalAlert(alertDescription);	            
		}
	        
		return maxFragmentLength;
	}
	
	public static int getCipherType(int ciphersuite) throws IOException
    {
        switch (getEncryptionAlgorithm(ciphersuite))
        {
        case EncryptionAlgorithm.AES_128_CCM:
        case EncryptionAlgorithm.AES_128_CCM_8:
        case EncryptionAlgorithm.AES_128_GCM:
        case EncryptionAlgorithm.AES_128_OCB_TAGLEN96:
        case EncryptionAlgorithm.AES_256_CCM:
        case EncryptionAlgorithm.AES_256_CCM_8:
        case EncryptionAlgorithm.AES_256_GCM:
        case EncryptionAlgorithm.AES_256_OCB_TAGLEN96:
        case EncryptionAlgorithm.CAMELLIA_128_GCM:
        case EncryptionAlgorithm.CAMELLIA_256_GCM:
        case EncryptionAlgorithm.CHACHA20_POLY1305:
            return CipherType.aead;

        case EncryptionAlgorithm.RC2_CBC_40:
        case EncryptionAlgorithm.IDEA_CBC:
        case EncryptionAlgorithm.DES40_CBC:
        case EncryptionAlgorithm.DES_CBC:
        case EncryptionAlgorithm._3DES_EDE_CBC:
        case EncryptionAlgorithm.AES_128_CBC:
        case EncryptionAlgorithm.AES_256_CBC:
        case EncryptionAlgorithm.CAMELLIA_128_CBC:
        case EncryptionAlgorithm.CAMELLIA_256_CBC:
        case EncryptionAlgorithm.SEED_CBC:
            return CipherType.block;

        case EncryptionAlgorithm.NULL:
        case EncryptionAlgorithm.RC4_40:
        case EncryptionAlgorithm.RC4_128:
            return CipherType.stream;

        default:
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
	public static int getEncryptionAlgorithm(int ciphersuite) throws IOException
    {
        switch (ciphersuite)
        {
	        case CipherSuite.TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA:
	        case CipherSuite.TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA:
	            return EncryptionAlgorithm._3DES_EDE_CBC;
	
	        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_anon_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA:
	        case CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA:
	            return EncryptionAlgorithm.AES_128_CBC;
	
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
	        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
	        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
	            return EncryptionAlgorithm.AES_128_CCM;
	
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
	            return EncryptionAlgorithm.AES_128_CCM_8;
	
	        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
	            return EncryptionAlgorithm.AES_128_GCM;
	
	        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
	        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
	        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
	            return EncryptionAlgorithm.AES_128_OCB_TAGLEN96;
	
	        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_anon_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA:
	        case CipherSuite.TLS_SRP_SHA_WITH_AES_256_CBC_SHA:
	            return EncryptionAlgorithm.AES_256_CBC;
	
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
	        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
	        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
	            return EncryptionAlgorithm.AES_256_CCM;
	
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
	        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
	        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
	        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
	            return EncryptionAlgorithm.AES_256_CCM_8;
	
	        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
	            return EncryptionAlgorithm.AES_256_GCM;
	
	        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
	        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
	        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
	            return EncryptionAlgorithm.AES_256_OCB_TAGLEN96;
	
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA:
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256:
	            return EncryptionAlgorithm.CAMELLIA_128_CBC;
	
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	            return EncryptionAlgorithm.CAMELLIA_128_GCM;
	
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA:
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
	            return EncryptionAlgorithm.CAMELLIA_256_CBC;
	
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	            return EncryptionAlgorithm.CAMELLIA_256_GCM;
	
	        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
	            return EncryptionAlgorithm.CHACHA20_POLY1305;
	
	        case CipherSuite.TLS_RSA_WITH_NULL_MD5:
	            return EncryptionAlgorithm.NULL;
	
	        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA:
	        case CipherSuite.TLS_ECDH_anon_WITH_NULL_SHA:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_NULL_SHA:
	        case CipherSuite.TLS_ECDH_RSA_WITH_NULL_SHA:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA:
	        case CipherSuite.TLS_PSK_WITH_NULL_SHA:
	        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA:
	        case CipherSuite.TLS_RSA_WITH_NULL_SHA:
	            return EncryptionAlgorithm.NULL;
	
	        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA256:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA256:
	        case CipherSuite.TLS_PSK_WITH_NULL_SHA256:
	        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA256:
	        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
	            return EncryptionAlgorithm.NULL;
	
	        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
	        case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
	            return EncryptionAlgorithm.NULL;
	
	        case CipherSuite.TLS_DH_anon_WITH_RC4_128_MD5:
	        case CipherSuite.TLS_RSA_WITH_RC4_128_MD5:
	            return EncryptionAlgorithm.RC4_128;
	
	        case CipherSuite.TLS_DHE_PSK_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_ECDH_anon_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_PSK_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_RSA_WITH_RC4_128_SHA:
	        case CipherSuite.TLS_RSA_PSK_WITH_RC4_128_SHA:
	            return EncryptionAlgorithm.RC4_128;
	
	        case CipherSuite.TLS_DH_anon_WITH_SEED_CBC_SHA:
	        case CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA:
	        case CipherSuite.TLS_DH_RSA_WITH_SEED_CBC_SHA:
	        case CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA:
	        case CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA:
	        case CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA:
	            return EncryptionAlgorithm.SEED_CBC;
	
	        default:
	            throw new TlsFatalAlert(AlertDescription.internal_error);
        }
    }
	
	public static int getPRFAlgorithm(ProtocolVersion version, int ciphersuite) throws IOException
    {
        boolean isTLSv12 = ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());

        switch (ciphersuite)
        {
	        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
	        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
	        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
	        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
	        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
	        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
	        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
	        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
	        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
	        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
	        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
	        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
	        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
	        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
	        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
	        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
	        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
	        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
	        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
	        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
	            if (isTLSv12)
	                return PRFAlgorithm.tls_prf_sha256;
	            
	            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
	        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
	        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
	        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
	            if (isTLSv12)
	                return PRFAlgorithm.tls_prf_sha384;
	            
	            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
	        
	        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_ECDHE_PSK_WITH_NULL_SHA384:
	        case CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_PSK_WITH_NULL_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384:
	        case CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384:
	            if (isTLSv12)
	                return PRFAlgorithm.tls_prf_sha384;
	            
	            return PRFAlgorithm.tls_prf_legacy;
	        default:
	            if (isTLSv12)
	                return PRFAlgorithm.tls_prf_sha256;
	            
	            return PRFAlgorithm.tls_prf_legacy;        
        }
    }
	
	public static ProtocolVersion getMinimumVersion(int ciphersuite)
    {
        switch (ciphersuite)
        {
        case CipherSuite.TLS_DH_anon_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_128_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_AES_256_OCB:
        case CipherSuite.DRAFT_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_128_OCB:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_AES_256_OCB:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384:
        case CipherSuite.TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_128_OCB:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM:
        case CipherSuite.TLS_PSK_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_PSK_WITH_AES_256_OCB:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.DRAFT_TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_128_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM:
        case CipherSuite.TLS_RSA_WITH_AES_256_CCM_8:
        case CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256:
        case CipherSuite.TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384:
        case CipherSuite.TLS_RSA_WITH_NULL_SHA256:
            return ProtocolVersion.TLSv12;

        default:
            return ProtocolVersion.SSLv3;
        }
    }
	
	public static Integer calculateExtensionsLength(Hashtable<Integer,byte[]> extensions) throws IOException
	{
		Integer length=0;
		length+=calculateSelectedExtensionsLength(extensions, true);
		length+=calculateSelectedExtensionsLength(extensions, false);
		
		if((length & 0xFFFF) != length)
			throw new TlsFatalAlert(AlertDescription.internal_error);
		
		return length+2;
	}
	
	public static void writeExtensions(ByteBuf buffer, Hashtable<Integer,byte[]> extensions) throws IOException
	{
		Integer length=0;
		length+=calculateSelectedExtensionsLength(extensions, true);
		length+=calculateSelectedExtensionsLength(extensions, false);
		
		if((length & 0xFFFF) != length)
			throw new TlsFatalAlert(AlertDescription.internal_error);
		
		buffer.writeShort(length);
		
		writeSelectedExtensions(buffer, extensions, true);
		writeSelectedExtensions(buffer, extensions, false);
	}

	public static Integer calculateSelectedExtensionsLength(Hashtable<Integer,byte[]> extensions, boolean selectEmpty) throws IOException
	{
		Integer length=0;
		Enumeration<Integer> keys = extensions.keys();
		while (keys.hasMoreElements())
		{
			Integer key = keys.nextElement();
			int extension_type = key.intValue();
			byte[] extension_data = extensions.get(key);

			if (selectEmpty == (extension_data.length == 0))
			{
				if((extension_type & 0xFFFF) != extension_type)
					throw new TlsFatalAlert(AlertDescription.internal_error);
				
				length+=4+extension_data.length;
			}
		}
		
		return length;
	}
	
	public static void writeSelectedExtensions(ByteBuf output, Hashtable<Integer,byte[]> extensions, boolean selectEmpty) throws IOException
	{
		Enumeration<Integer> keys = extensions.keys();
		while (keys.hasMoreElements())
		{
			Integer key = keys.nextElement();
			int extension_type = key.intValue();
			byte[] extension_data = extensions.get(key);

			if (selectEmpty == (extension_data.length == 0))
			{
				output.writeShort(extension_type);
				output.writeShort(extension_data.length);
				output.writeBytes(extension_data);				
			}
		}
	}
	
	public static Hashtable<Integer,byte[]> readSelectedExtensions(ByteBuf output) throws IOException
	{
		int extentionsLength=output.readUnsignedShort();
		Hashtable<Integer,byte[]> extensions = new Hashtable<Integer,byte[]>();
        while (extentionsLength > 0)
        {        	
            Integer extension_type = output.readUnsignedShort();
            byte[] extension_data = new byte[output.readUnsignedShort()];
            output.readBytes(extension_data);
            
            if (null != extensions.put(extension_type, extension_data))
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            
            extentionsLength-=4+extension_data.length;
        }

        return extensions;
	}
	
	public static Integer calculateSupplementalDataLength(Vector<SupplementalDataEntry> supplementalData) throws IOException
	{
		Integer length=0;
		for (int i = 0; i < supplementalData.size(); ++i)
        {
            SupplementalDataEntry entry = supplementalData.elementAt(i);
            length+=4+entry.getData().length;
        }
		
		return length;
	}
	
	public static void writeSupplementalData(ByteBuf output, Vector<SupplementalDataEntry> supplementalData) throws IOException
	{
		for (int i = 0; i < supplementalData.size(); ++i)
        {
            SupplementalDataEntry entry = supplementalData.elementAt(i);
            output.writeShort(entry.getDataType());
			output.writeShort(entry.getData().length);
			output.writeBytes(entry.getData());		
        }
	}
	
	public static Vector<SupplementalDataEntry> readSupplementalData(ByteBuf output) throws IOException
	{
		int suppDataLength=readUint24(output);
		Vector<SupplementalDataEntry> result=new Vector<SupplementalDataEntry>();
		while(suppDataLength>0)
		{
			int supp_data_type = output.readUnsignedShort();
            byte[] data = new byte[output.readUnsignedShort()];
            output.readBytes(data);
            result.addElement(new SupplementalDataEntry(supp_data_type, data));
		}
		
		return result;
	}
	
	public static ByteBuf writeCertificate(short messageSequence,Certificate certificate)throws IOException
	{
		int totalLength = HANDSHAKE_MESSAGE_HEADER_LENGTH;
		List<byte[]> derEncodings=new ArrayList<byte[]>();
		for (int i = 0; i < certificate.getCertificateList().length; ++i)
		{
			byte[] derEncoding = certificate.getCertificateList()[i].getEncoded(ASN1Encoding.DER);
			derEncodings.add(derEncoding);
			totalLength += derEncoding.length + 3;
		}

		totalLength+=3;
		ByteBuf output=Unpooled.buffer(totalLength);
		totalLength-=HANDSHAKE_MESSAGE_HEADER_LENGTH;
		DtlsHelper.writeHandshakeHeader(messageSequence,MessageType.CERTIFICATE,output,totalLength);
		totalLength-=3;
		output.writeByte((byte)(totalLength >>> 16));
        output.writeByte((byte)(totalLength >>> 8));
        output.writeByte((byte)totalLength);
        
		for (int i = 0; i < derEncodings.size(); ++i)
		{
			byte[] curr=derEncodings.get(i);
			output.writeByte((byte)(curr.length >>> 16));
	        output.writeByte((byte)(curr.length >>> 8));
	        output.writeByte((byte)curr.length);
	        output.writeBytes(curr);
		}
		
		return output;
	}
	
	public static ByteBuf writeCertificateList(short messageSequence,org.bouncycastle.asn1.x509.Certificate[] list)throws IOException
	{
		int totalLength = HANDSHAKE_MESSAGE_HEADER_LENGTH;
		List<byte[]> derEncodings=new ArrayList<byte[]>();
		for (int i = 0; i < list.length; ++i)
		{
			byte[] derEncoding = list[i].getEncoded(ASN1Encoding.DER);
			derEncodings.add(derEncoding);
			totalLength += derEncoding.length + 3;
		}

		ByteBuf output=Unpooled.buffer(totalLength+3);
		totalLength-=HANDSHAKE_MESSAGE_HEADER_LENGTH;
		DtlsHelper.writeHandshakeHeader(messageSequence,MessageType.CERTIFICATE,output,totalLength+3);
		output.writeByte((byte)(totalLength >>> 16));
        output.writeByte((byte)(totalLength >>> 8));
        output.writeByte((byte)totalLength);
        
		for (int i = 0; i < derEncodings.size(); ++i)
		{
			byte[] curr=derEncodings.get(i);
			output.writeByte((byte)(curr.length >>> 16));
	        output.writeByte((byte)(curr.length >>> 8));
	        output.writeByte((byte)curr.length);
	        output.writeBytes(curr);
		}
		
		return output;
	}
	
	public static ByteBuf writeCertificateStatus(short messageSequence,CertificateStatus status) throws IOException
	{		
		ByteBuf output;
		switch (status.getStatusType())
	    {
	        case CertificateStatusType.ocsp:
	            byte[] derEncoding = ((OCSPResponse) status.getOCSPResponse()).getEncoded(ASN1Encoding.DER);
	            
	            output=Unpooled.buffer(HANDSHAKE_MESSAGE_HEADER_LENGTH + derEncoding.length+4);
	            DtlsHelper.writeHandshakeHeader(messageSequence,MessageType.CERTIFICATE_STATUS,output,derEncoding.length+4);
	            output.writeByte(status.getStatusType());
	            output.writeByte((byte)(derEncoding.length >>> 16));
		        output.writeByte((byte)(derEncoding.length >>> 8));
		        output.writeByte((byte)derEncoding.length);
		        output.writeBytes(derEncoding);
	            break;
	        default:
	            throw new TlsFatalAlert(AlertDescription.internal_error);
	    }
		
		return output;
	}
	
	public static Digest createHash(short hashAlgorithm)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return new MD5Digest();
        case HashAlgorithm.sha1:
            return new SHA1Digest();
        case HashAlgorithm.sha224:
            return new SHA224Digest();
        case HashAlgorithm.sha256:
            return new SHA256Digest();
        case HashAlgorithm.sha384:
            return new SHA384Digest();
        case HashAlgorithm.sha512:
            return new SHA512Digest();
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }
	
	public static Digest cloneHash(short hashAlgorithm, Digest hash)
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithm.md5:
            return new MD5Digest((MD5Digest)hash);
        case HashAlgorithm.sha1:
            return new SHA1Digest((SHA1Digest)hash);
        case HashAlgorithm.sha224:
            return new SHA224Digest((SHA224Digest)hash);
        case HashAlgorithm.sha256:
            return new SHA256Digest((SHA256Digest)hash);
        case HashAlgorithm.sha384:
            return new SHA384Digest((SHA384Digest)hash);
        case HashAlgorithm.sha512:
            return new SHA512Digest((SHA512Digest)hash);
        default:
            throw new IllegalArgumentException("unknown HashAlgorithm");
        }
    }
	
	public static byte[] genPad(byte b, int count)
    {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }
	
	public static Integer calculateNewTicketLength(NewSessionTicket ticket) throws IOException
	{
		return 6 + ticket.getTicket().length;
	}
	
	public static void writeNewTicket(ByteBuf buffer, NewSessionTicket ticket) throws IOException
	{
		buffer.writeInt((int)ticket.getTicketLifetimeHint());
		buffer.writeShort(ticket.getTicket().length);
		buffer.writeBytes(ticket.getTicket());
	}
	
	public static byte[] PRF(TlsContext context, byte[] secret, String asciiLabel, byte[] seed, int size)
    {
        ProtocolVersion version = context.getServerVersion();

        if (version.isSSL())
        {
            throw new IllegalStateException("No PRF available for SSLv3 session");
        }

        byte[] label = asciiLabel.getBytes();
        byte[] labelSeed = new byte[label.length + seed.length];
        System.arraycopy(label, 0, labelSeed, 0, label.length);
        System.arraycopy(seed, 0, labelSeed, label.length, seed.length);
        
        int prfAlgorithm = context.getSecurityParameters().getPrfAlgorithm();

        if (prfAlgorithm == PRFAlgorithm.tls_prf_legacy)
            return PRF_legacy(secret, label, labelSeed, size);
        
        Digest prfDigest=null;
        switch (prfAlgorithm)
        {
        	case PRFAlgorithm.tls_prf_legacy:
        		prfDigest = new CombinedHash();
        		break;
        	case PRFAlgorithm.tls_prf_sha256:
        		prfDigest =  new SHA256Digest();
                break;
            case PRFAlgorithm.tls_prf_sha384:
            	prfDigest = new SHA384Digest();
                break;
        }
        
        byte[] buf = new byte[size];
        hmac_hash(prfDigest, secret, labelSeed, buf);
        return buf;
    }
	
	public static void hmac_hash(Digest digest, byte[] secret, byte[] seed, byte[] out)
    {
        HMac mac = new HMac(digest);
        mac.init(new KeyParameter(secret));
        byte[] a = seed;
        int size = digest.getDigestSize();
        int iterations = (out.length + size - 1) / size;
        byte[] buf = new byte[mac.getMacSize()];
        byte[] buf2 = new byte[mac.getMacSize()];
        for (int i = 0; i < iterations; i++)
        {
            mac.update(a, 0, a.length);
            mac.doFinal(buf, 0);
            a = buf;
            mac.update(a, 0, a.length);
            mac.update(seed, 0, seed.length);
            mac.doFinal(buf2, 0);
            System.arraycopy(buf2, 0, out, (size * i), Math.min(size, out.length - (size * i)));
        }
    }
	
	public static byte[] calculateVerifyData(TlsContext context, String asciiLabel, byte[] handshakeHash)
    {
		if (context.getServerVersion().isSSL())
            return handshakeHash;
        
        SecurityParameters securityParameters = context.getSecurityParameters();
        byte[] master_secret = securityParameters.getMasterSecret();
        int verify_data_length = securityParameters.getVerifyDataLength();

        return PRF(context, master_secret, asciiLabel, handshakeHash, verify_data_length);
    }
	
	public static void verifySupportedSignatureAlgorithm(Vector<SignatureAndHashAlgorithm> supportedSignatureAlgorithms, SignatureAndHashAlgorithm signatureAlgorithm) throws IOException
	{
		if (supportedSignatureAlgorithms == null || supportedSignatureAlgorithms.size() < 1 || supportedSignatureAlgorithms.size() >= (1 << 15))
			throw new IllegalArgumentException("'supportedSignatureAlgorithms' must have length from 1 to (2^15 - 1)");
	        
		if (signatureAlgorithm == null)
			throw new IllegalArgumentException("'signatureAlgorithm' cannot be null");
	        
		if (signatureAlgorithm.getSignature() != SignatureAlgorithm.anonymous)
		{
			for (int i = 0; i < supportedSignatureAlgorithms.size(); ++i)
			{
				SignatureAndHashAlgorithm entry = supportedSignatureAlgorithms.elementAt(i);
				if (entry.getHash() == signatureAlgorithm.getHash() && entry.getSignature() == signatureAlgorithm.getSignature())
					return;
			}
		}

		throw new TlsFatalAlert(AlertDescription.illegal_parameter);
	}
	
	public static byte[] PRF_legacy(byte[] secret, byte[] label, byte[] labelSeed, int size)
    {
        int s_half = (secret.length + 1) / 2;
        byte[] s1 = new byte[s_half];
        byte[] s2 = new byte[s_half];
        System.arraycopy(secret, 0, s1, 0, s_half);
        System.arraycopy(secret, secret.length - s_half, s2, 0, s_half);

        byte[] b1 = new byte[size];
        byte[] b2 = new byte[size];
        hmac_hash(createHash(HashAlgorithm.md5), s1, labelSeed, b1);
        hmac_hash(createHash(HashAlgorithm.sha1), s2, labelSeed, b2);
        for (int i = 0; i < size; i++)
        {
            b1[i] ^= b2[i];
        }
        return b1;
    }
	
	public static byte[] getCurrentPRFHash(TlsContext context, TlsHandshakeHash handshakeHash, byte[] sslSender)
    {
        Digest d = handshakeHash.forkPRFHash();
        if (sslSender != null && context.getServerVersion().isSSL())
            d.update(sslSender, 0, sslSender.length);
        
        byte[] bs = new byte[d.getDigestSize()];
        d.doFinal(bs, 0);
        return bs;
    }
	
	public static short getClientCertificateType(Certificate clientCertificate, Certificate serverCertificate) throws IOException
	{
		if (clientCertificate.isEmpty())
			return -1;
	    
		org.bouncycastle.asn1.x509.Certificate x509Cert = clientCertificate.getCertificateAt(0);
		SubjectPublicKeyInfo keyInfo = x509Cert.getSubjectPublicKeyInfo();
		try
		{
			AsymmetricKeyParameter publicKey = PublicKeyFactory.createKey(keyInfo);
			if (publicKey.isPrivate())
				throw new TlsFatalAlert(AlertDescription.internal_error);
	        
			if (publicKey instanceof RSAKeyParameters)
			{
				validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
	            return ClientCertificateType.rsa_sign;
			}

			if (publicKey instanceof DSAPublicKeyParameters)
	        {
				validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
	            return ClientCertificateType.dss_sign;
	        }

	        if (publicKey instanceof ECPublicKeyParameters)
	        {
	        	validateKeyUsage(x509Cert, KeyUsage.digitalSignature);
	            return ClientCertificateType.ecdsa_sign;
	        }

	        throw new TlsFatalAlert(AlertDescription.unsupported_certificate);
		}
		catch (Exception e)
		{
			throw new TlsFatalAlert(AlertDescription.unsupported_certificate, e);
		}
	}
	
	public static void validateKeyUsage(org.bouncycastle.asn1.x509.Certificate c, int keyUsageBits) throws IOException
	{
		Extensions exts = c.getTBSCertificate().getExtensions();
	    if (exts != null)
	    {
	    	KeyUsage ku = KeyUsage.fromExtensions(exts);
	        if (ku != null)
	        {
	        	int bits = ku.getBytes()[0] & 0xff;
	            if ((bits & keyUsageBits) != keyUsageBits)
	            	throw new TlsFatalAlert(AlertDescription.certificate_unknown);
	        }
	    }
	}
	
	public static void establishMasterSecret(AsyncDtlsSecurityParameters securityParameters, TlsContext context, TlsKeyExchange keyExchange) throws IOException
	{
		byte[] pre_master_secret = keyExchange.generatePremasterSecret();

	    try
	    {
	    	securityParameters.setMasterSecret(calculateMasterSecret(securityParameters, context, pre_master_secret));
	    }
	    finally
	    {
	    	if (pre_master_secret != null)
	    		Arrays.fill(pre_master_secret, (byte)0);
	    }
	}
	
	public static byte[] calculateMasterSecret(AsyncDtlsSecurityParameters securityParameters, TlsContext context, byte[] pre_master_secret)
    {
        byte[] seed;
        if (securityParameters.isExtendedMasterSecret())
            seed = securityParameters.getSessionHash();
        else
        {
        	seed=new byte[securityParameters.getClientRandom().length + securityParameters.getServerRandom().length];
        	System.arraycopy(securityParameters.getClientRandom(), 0, seed, 0, securityParameters.getClientRandom().length);
        	System.arraycopy(securityParameters.getServerRandom(), 0, seed, securityParameters.getClientRandom().length, securityParameters.getServerRandom().length);            
        }
        
        if (context.getServerVersion().isSSL())
            return calculateMasterSecret_SSL(pre_master_secret, seed);
        
        String asciiLabel = securityParameters.isExtendedMasterSecret() ? ExporterLabel.extended_master_secret : ExporterLabel.master_secret;

        return PRF(context, pre_master_secret, asciiLabel, seed, 48);
    }

    public static byte[] calculateMasterSecret_SSL(byte[] pre_master_secret, byte[] random)
    {
        Digest md5 = createHash(HashAlgorithm.md5);
        Digest sha1 = createHash(HashAlgorithm.sha1);
        int md5Size = md5.getDigestSize();
        byte[] shatmp = new byte[sha1.getDigestSize()];

        byte[] rval = new byte[md5Size * 3];
        int pos = 0;

        for (int i = 0; i < 3; ++i)
        {
            byte[] ssl3Const = SSL3_CONST[i];

            sha1.update(ssl3Const, 0, ssl3Const.length);
            sha1.update(pre_master_secret, 0, pre_master_secret.length);
            sha1.update(random, 0, random.length);
            sha1.doFinal(shatmp, 0);

            md5.update(pre_master_secret, 0, pre_master_secret.length);
            md5.update(shatmp, 0, shatmp.length);
            md5.doFinal(rval, pos);

            pos += md5Size;
        }

        return rval;
    }
    
    public static ASN1Primitive readASN1Object(byte[] encoding) throws IOException
    {
        ASN1InputStream asn1 = new ASN1InputStream(encoding);
        ASN1Primitive result = asn1.readObject();
        asn1.close();
        
        if (null == result)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        if (null != asn1.readObject())
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }
        return result;
    }
    
    public static SignatureAndHashAlgorithm getSignatureAndHashAlgorithm(TlsContext context, TlsSignerCredentials signerCredentials) throws IOException
    {
    	SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
    	if (ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(context.getServerVersion().getEquivalentTLSVersion()))
    	{
    		signatureAndHashAlgorithm = signerCredentials.getSignatureAndHashAlgorithm();
    		if (signatureAndHashAlgorithm == null)
    			throw new TlsFatalAlert(AlertDescription.internal_error);
    	}
    	return signatureAndHashAlgorithm;
    }
    
    public static SignatureAndHashAlgorithm parseSignatureAndHashAlgorithm(ByteBuf data) throws IOException
    {
    	short hash = data.readUnsignedByte();
    	short signature = data.readUnsignedByte();
    	return new SignatureAndHashAlgorithm(hash, signature);
    }
    
    public static Vector<SignatureAndHashAlgorithm> parseSupportedSignatureAlgorithms(boolean allowAnonymous, ByteBuf data) throws IOException
    {
    	int length = data.readUnsignedShort();
    	if (length < 2 || (length & 1) != 0)
    		throw new TlsFatalAlert(AlertDescription.decode_error);
            
    	int count = length / 2;
        Vector<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new Vector<SignatureAndHashAlgorithm>(count);
        for (int i = 0; i < count; ++i)
        {
        	SignatureAndHashAlgorithm entry = parseSignatureAndHashAlgorithm(data);
        	if (!allowAnonymous && entry.getSignature() == SignatureAlgorithm.anonymous)
                    throw new TlsFatalAlert(AlertDescription.illegal_parameter);
                
        	supportedSignatureAlgorithms.addElement(entry);
        }
        return supportedSignatureAlgorithms;
    }
    
    public static Certificate parseCertificate(ByteBuf data) throws IOException
    {
    	int totalLength = readUint24(data);
    	if (totalLength == 0)
    		return Certificate.EMPTY_CHAIN;
        
    	Vector<org.bouncycastle.asn1.x509.Certificate> certificate_list = new Vector<org.bouncycastle.asn1.x509.Certificate>();
    	while (data.readableBytes() > 0)
    	{
    		byte[] berEncoding = new byte[readUint24(data)];
    		data.readBytes(berEncoding);
    		ASN1Primitive asn1Cert = readASN1Object(berEncoding);
    		certificate_list.addElement(org.bouncycastle.asn1.x509.Certificate.getInstance(asn1Cert));
    	}

    	org.bouncycastle.asn1.x509.Certificate[] certificateList = new org.bouncycastle.asn1.x509.Certificate[certificate_list.size()];
    	for (int i = 0; i < certificate_list.size(); i++)
    		certificateList[i] = certificate_list.elementAt(i);
    	    
    	return new Certificate(certificateList);
    }
    
    public static CertificateStatus parseCertificateStatus(ByteBuf data) throws IOException
    {
    	short status_type = data.readUnsignedByte();
        Object response;

        switch (status_type)
        {
	        case CertificateStatusType.ocsp:
	        {
	            byte[] derEncoding = new byte[readUint24(data)];
	            data.readBytes(derEncoding);
	            
	            ASN1InputStream asn1 = new ASN1InputStream(derEncoding);
	            ASN1Primitive result = asn1.readObject();
	            asn1.close();
	            if (null == result)
	                throw new TlsFatalAlert(AlertDescription.decode_error);
	            
	            if (null != asn1.readObject())
	                throw new TlsFatalAlert(AlertDescription.decode_error);
	            
	            response = OCSPResponse.getInstance(result);
	            break;
	        }
	        default:
	            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        return new CertificateStatus(status_type, response);
    }
    
    public static byte[] createRandomBlock(boolean useGMTUnixTime, RandomGenerator randomGenerator)
    {
        byte[] result = new byte[32];
        randomGenerator.nextBytes(result);

        if (useGMTUnixTime)
            writeGMTUnixTime(result, 0);
       
        return result;
    }
    
    public static void writeGMTUnixTime(byte[] buf, int offset)
    {
        int t = (int)(System.currentTimeMillis() / 1000L);
        buf[offset] = (byte)(t >>> 24);
        buf[offset + 1] = (byte)(t >>> 16);
        buf[offset + 2] = (byte)(t >>> 8);
        buf[offset + 3] = (byte)t;
    } 
    
    public static int readUint24(ByteBuf buf)
	{
		int result=(buf.readShort()<<8);
		result|=(buf.readByte() & 0x0FF);
		return result;
	}
	
	public static long readUint48(ByteBuf buf)
	{
		long result=((long)buf.readInt())<<16;
		result|=(long)(buf.readShort() & 0x0FFFF);
		return result;
	}
	
	public static void writeUint48(Long value,ByteBuf buf)
	{
		buf.writeInt((int)((value>>16) & 0x0FFFFFFFF));
		buf.writeShort((short)(value&0x0FFFF));
	}
	
	public static void writeHandshakeHeader(short messageSequence,MessageType messageType,ByteBuf buffer,int totalLength)
	{
		//message type
		buffer.writeByte(messageType.getValue());
		//length
		buffer.writeByte((byte)(totalLength >>> 16));
		buffer.writeByte((byte)(totalLength >>> 8));
		buffer.writeByte((byte)totalLength);
        //message sequence
		buffer.writeShort(messageSequence);
		//fragment offset
		buffer.writeByte(0);
		buffer.writeByte(0);
		buffer.writeByte(0);
        //fragment length
        buffer.writeByte((byte)(totalLength >>> 16));
		buffer.writeByte((byte)(totalLength >>> 8));
		buffer.writeByte((byte)totalLength);
	}
	
	public static void writeHandshakeHeader(int fragmentOffset,int fragmentLength,short messageSequence,MessageType messageType,ByteBuf buffer,int totalLength)
	{
		//message type
		buffer.writeByte(messageType.getValue());
		//length
		buffer.writeByte((byte)(totalLength >>> 16));
		buffer.writeByte((byte)(totalLength >>> 8));
		buffer.writeByte((byte)totalLength);
        //message sequence
		buffer.writeShort(messageSequence);
		//fragment offset
		buffer.writeByte((byte)(fragmentOffset >>> 16));
		buffer.writeByte((byte)(fragmentOffset >>> 8));
		buffer.writeByte((byte)fragmentOffset);
        //fragment length
        buffer.writeByte((byte)(fragmentLength >>> 16));
		buffer.writeByte((byte)(fragmentLength >>> 8));
		buffer.writeByte((byte)fragmentLength);
	}
	
	public static HandshakeHeader readHandshakeHeader(ByteBuf data)
	{		
		MessageType messageType=MessageType.fromInt(data.readByte());
		Integer totalLength=readUint24(data);
		Short messageSequence=data.readShort();
		Integer fragmentOffset=readUint24(data);
		Integer fragmentLength=readUint24(data);
		return new HandshakeHeader(fragmentOffset, fragmentLength, totalLength, messageType, messageSequence);		
	}
}