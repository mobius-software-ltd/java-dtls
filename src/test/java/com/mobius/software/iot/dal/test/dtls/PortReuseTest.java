package com.mobius.software.iot.dal.test.dtls;

import static org.junit.Assert.assertEquals;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Certificate;
import org.junit.Before;
import org.junit.Test;

import com.mobius.software.iot.dal.crypto.MessageType;

public class PortReuseTest 
{
	private static final String keystorePassword="GfUNokaofNh6";
	private static final String clientKeystorePassword="qwe321";	
	private final static Logger logger = Logger.getLogger(PortReuseTest.class);
    
	@Before
    public void setUp() 
    {
    	 BasicConfigurator.resetConfiguration();
         BasicConfigurator.configure();         
    }
	
	@Test
	public void testPortReuseByClient() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateEncodingException, IOException
	{
		KeyStore testKeystore = null;
		try
		{
			testKeystore=KeyStore.getInstance("JKS");
			testKeystore.load(this.getClass().getClassLoader().getResourceAsStream("dtls-demo.jks"), keystorePassword.toCharArray());
		}		
		catch(Exception ex)
		{
			logger.error("An error occured while reading keystore,",ex);
			ex.printStackTrace();
			assertEquals(1,2);
		}
		
		KeyStore clientKeystore = null;
		try
		{
			clientKeystore=KeyStore.getInstance("PKCS12");
			clientKeystore.load(this.getClass().getClassLoader().getResourceAsStream("p.pfx"), clientKeystorePassword.toCharArray());
		}		
		catch(Exception ex)
		{
			logger.error("An error occured while reading client keystore,",ex);
			ex.printStackTrace();
			assertEquals(1,2);
		}
		
		logger.info("Initializing server and client");
		
		DtlsServer server=new DtlsServer("0.0.0.0", 5555,testKeystore,keystorePassword,null,null);
		server.initServer();
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		//using fixed port to connect
		DtlsClient client=new DtlsClient("127.0.0.1","127.0.0.1",5555,18555,clientKeystore,clientKeystorePassword);
		client.establishConnection();
		
		logger.info("All set up,testing");
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		byte[] testBytes="hello message".getBytes();
		ByteBuf buffer=Unpooled.wrappedBuffer(testBytes);
		
		byte[] test2Bytes="server hello message".getBytes();
		ByteBuf buffer2=Unpooled.wrappedBuffer(test2Bytes);
		try
		{
			client.sendPacket(buffer);
			server.sendMessage((InetSocketAddress)client.getLocalAddress(), buffer2);
		}
		catch(Exception ex)
		{
			
		}
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		client.shutdown();
		
		//verifying certificates received
		Certificate[] certificateList=client.getServerCertificate().getCertificateList();
		Enumeration<String> aliases=testKeystore.aliases();
		Integer count = 0;
		while(aliases.hasMoreElements())
		{
			String alias=aliases.nextElement();
			X509Certificate currCertificate = (X509Certificate) testKeystore.getCertificate(alias);
			if(currCertificate!=null)
			{
				Boolean found=false;
				for(int i=0;i<certificateList.length;i++)
				{
					if(Arrays.equals(certificateList[i].getEncoded(),currCertificate.getEncoded()))
					{
						found=true;
						break;
					}
				}
				
				assertEquals(found,true);
				count++;
			}
		}
		
		assertEquals(new Integer(certificateList.length),count);
		
		//now checking client certificates
		certificateList=server.getCertificate((InetSocketAddress)client.getLocalAddress()).getCertificateList();
		aliases=clientKeystore.aliases();
		count = 0;
		while(aliases.hasMoreElements())
		{
			String alias=aliases.nextElement();
			X509Certificate currCertificate = (X509Certificate) clientKeystore.getCertificate(alias);
			if(currCertificate!=null)
			{
				Boolean found=false;
				for(int i=0;i<certificateList.length;i++)
				{
					if(Arrays.equals(certificateList[i].getEncoded(),currCertificate.getEncoded()))
					{
						found=true;
						break;
					}
				}
				
				assertEquals(found,true);
				count++;
			}
		}
		
		assertEquals(new Integer(certificateList.length),count);
		
		//verifying that all handshake messages received
		assertEquals(server.handshakeMessagesReceived(MessageType.CLIENT_HELLO),new Integer(2));
		assertEquals(server.handshakeMessagesReceived(MessageType.CERTIFICATE),new Integer(1));
		assertEquals(server.handshakeMessagesReceived(MessageType.CLIENT_KEY_EXCHANGE),new Integer(1));
		assertEquals(server.handshakeMessagesReceived(MessageType.CERTIFICATE_VERIFY),new Integer(1));
		assertEquals(server.handshakeMessagesReceived(MessageType.FINISHED),new Integer(1));
		
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_HELLO),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.CERTIFICATE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_KEY_EXCHANGE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.CERTIFICATE_REQUEST),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_HELLO_DONE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.FINISHED),new Integer(1));
		
		//verifying messages itself
		assertEquals(server.getMessagesReceived(),new Integer(1));
		assertEquals(client.getMessagesReceived(),new Integer(1));
		assertEquals(server.getMessage(0),"hello message");
		assertEquals(client.getMessage(0),"server hello message");
		
		//SECOND ITERATION
		logger.info("Second Iteration");
		client=new DtlsClient("127.0.0.1","127.0.0.1",5555,18555,clientKeystore,clientKeystorePassword);
		client.establishConnection();
		
		logger.info("All set up,testing");
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		buffer=Unpooled.wrappedBuffer(testBytes);
		buffer2=Unpooled.wrappedBuffer(test2Bytes);
		
		try
		{
			client.sendPacket(buffer);
			server.sendMessage((InetSocketAddress)client.getLocalAddress(), buffer2);
		}
		catch(Exception ex)
		{
			
		}
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		client.shutdown();
		server.terminate();
		
		//verifying certificates received
		certificateList=client.getServerCertificate().getCertificateList();
		aliases=testKeystore.aliases();
		count = 0;
		while(aliases.hasMoreElements())
		{
			String alias=aliases.nextElement();
			X509Certificate currCertificate = (X509Certificate) testKeystore.getCertificate(alias);
			if(currCertificate!=null)
			{
				Boolean found=false;
				for(int i=0;i<certificateList.length;i++)
				{
					if(Arrays.equals(certificateList[i].getEncoded(),currCertificate.getEncoded()))
					{
						found=true;
						break;
					}
				}
				
				assertEquals(found,true);
				count++;
			}
		}
		
		assertEquals(new Integer(certificateList.length),count);
		
		//now checking client certificates
		certificateList=server.getCertificate((InetSocketAddress)client.getLocalAddress()).getCertificateList();
		aliases=clientKeystore.aliases();
		count = 0;
		while(aliases.hasMoreElements())
		{
			String alias=aliases.nextElement();
			X509Certificate currCertificate = (X509Certificate) clientKeystore.getCertificate(alias);
			if(currCertificate!=null)
			{
				Boolean found=false;
				for(int i=0;i<certificateList.length;i++)
				{
					if(Arrays.equals(certificateList[i].getEncoded(),currCertificate.getEncoded()))
					{
						found=true;
						break;
					}
				}
				
				assertEquals(found,true);
				count++;
			}
		}
		
		assertEquals(new Integer(certificateList.length),count);
		
		//verifying that all handshake messages received
		assertEquals(server.handshakeMessagesReceived(MessageType.CLIENT_HELLO),new Integer(4));
		assertEquals(server.handshakeMessagesReceived(MessageType.CERTIFICATE),new Integer(2));
		assertEquals(server.handshakeMessagesReceived(MessageType.CLIENT_KEY_EXCHANGE),new Integer(2));
		assertEquals(server.handshakeMessagesReceived(MessageType.CERTIFICATE_VERIFY),new Integer(2));
		assertEquals(server.handshakeMessagesReceived(MessageType.FINISHED),new Integer(2));
		
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_HELLO),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.CERTIFICATE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_KEY_EXCHANGE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.CERTIFICATE_REQUEST),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_HELLO_DONE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.FINISHED),new Integer(1));
		
		//verifying messages itself
		assertEquals(server.getMessagesReceived(),new Integer(2));
		assertEquals(client.getMessagesReceived(),new Integer(1));
		assertEquals(server.getMessage(0),"hello message");
		assertEquals(client.getMessage(0),"server hello message");
	}
	
	@Test
	public void testPortReuseByClientWithCleanup() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateEncodingException, IOException
	{
		KeyStore testKeystore = null;
		try
		{
			testKeystore=KeyStore.getInstance("JKS");
			testKeystore.load(this.getClass().getClassLoader().getResourceAsStream("dtls-demo.jks"), keystorePassword.toCharArray());
		}		
		catch(Exception ex)
		{
			logger.error("An error occured while reading keystore,",ex);
			ex.printStackTrace();
			assertEquals(1,2);
		}
		
		KeyStore clientKeystore = null;
		try
		{
			clientKeystore=KeyStore.getInstance("PKCS12");
			clientKeystore.load(this.getClass().getClassLoader().getResourceAsStream("p.pfx"), clientKeystorePassword.toCharArray());
		}		
		catch(Exception ex)
		{
			logger.error("An error occured while reading client keystore,",ex);
			ex.printStackTrace();
			assertEquals(1,2);
		}
		
		logger.info("Initializing server and client");
		
		DtlsServer server=new DtlsServer("0.0.0.0", 5555,testKeystore,keystorePassword,null,2000L);
		server.initServer();
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		//using fixed port to connect
		DtlsClient client=new DtlsClient("127.0.0.1","127.0.0.1",5555,18555,clientKeystore,clientKeystorePassword);
		client.establishConnection();
		
		logger.info("All set up,testing");
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		byte[] testBytes="hello message".getBytes();
		ByteBuf buffer=Unpooled.wrappedBuffer(testBytes);
		
		byte[] test2Bytes="server hello message".getBytes();
		ByteBuf buffer2=Unpooled.wrappedBuffer(test2Bytes);
		try
		{
			client.sendPacket(buffer);
			server.sendMessage((InetSocketAddress)client.getLocalAddress(), buffer2);
		}
		catch(Exception ex)
		{
			
		}
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		client.shutdown();
		
		//verifying certificates received
		Certificate[] certificateList=client.getServerCertificate().getCertificateList();
		Enumeration<String> aliases=testKeystore.aliases();
		Integer count = 0;
		while(aliases.hasMoreElements())
		{
			String alias=aliases.nextElement();
			X509Certificate currCertificate = (X509Certificate) testKeystore.getCertificate(alias);
			if(currCertificate!=null)
			{
				Boolean found=false;
				for(int i=0;i<certificateList.length;i++)
				{
					if(Arrays.equals(certificateList[i].getEncoded(),currCertificate.getEncoded()))
					{
						found=true;
						break;
					}
				}
				
				assertEquals(found,true);
				count++;
			}
		}
		
		assertEquals(new Integer(certificateList.length),count);
		
		//now checking client certificates
		certificateList=server.getCertificate((InetSocketAddress)client.getLocalAddress()).getCertificateList();
		aliases=clientKeystore.aliases();
		count = 0;
		while(aliases.hasMoreElements())
		{
			String alias=aliases.nextElement();
			X509Certificate currCertificate = (X509Certificate) clientKeystore.getCertificate(alias);
			if(currCertificate!=null)
			{
				Boolean found=false;
				for(int i=0;i<certificateList.length;i++)
				{
					if(Arrays.equals(certificateList[i].getEncoded(),currCertificate.getEncoded()))
					{
						found=true;
						break;
					}
				}
				
				assertEquals(found,true);
				count++;
			}
		}
		
		assertEquals(new Integer(certificateList.length),count);
		
		//verifying that all handshake messages received
		assertEquals(server.handshakeMessagesReceived(MessageType.CLIENT_HELLO),new Integer(2));
		assertEquals(server.handshakeMessagesReceived(MessageType.CERTIFICATE),new Integer(1));
		assertEquals(server.handshakeMessagesReceived(MessageType.CLIENT_KEY_EXCHANGE),new Integer(1));
		assertEquals(server.handshakeMessagesReceived(MessageType.CERTIFICATE_VERIFY),new Integer(1));
		assertEquals(server.handshakeMessagesReceived(MessageType.FINISHED),new Integer(1));
		
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_HELLO),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.CERTIFICATE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_KEY_EXCHANGE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.CERTIFICATE_REQUEST),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_HELLO_DONE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.FINISHED),new Integer(1));
		
		//verifying messages itself
		assertEquals(server.getMessagesReceived(),new Integer(1));
		assertEquals(client.getMessagesReceived(),new Integer(1));
		assertEquals(server.getMessage(0),"hello message");
		assertEquals(client.getMessage(0),"server hello message");
		
		//this time wait for cleanup , may take to iterations to cleanup
		try
		{
			Thread.sleep(10000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		//SECOND ITERATION
		logger.info("Second Iteration");
		client=new DtlsClient("127.0.0.1","127.0.0.1",5555,18555,clientKeystore,clientKeystorePassword);
		client.establishConnection();
		
		logger.info("All set up,testing");
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		buffer=Unpooled.wrappedBuffer(testBytes);
		buffer2=Unpooled.wrappedBuffer(test2Bytes);
		
		try
		{
			client.sendPacket(buffer);
			server.sendMessage((InetSocketAddress)client.getLocalAddress(), buffer2);
		}
		catch(Exception ex)
		{
			
		}
		
		try
		{
			Thread.sleep(1000);
		}
		catch(InterruptedException ex)
		{
			
		}
		
		client.shutdown();
		server.terminate();
		
		//verifying certificates received
		certificateList=client.getServerCertificate().getCertificateList();
		aliases=testKeystore.aliases();
		count = 0;
		while(aliases.hasMoreElements())
		{
			String alias=aliases.nextElement();
			X509Certificate currCertificate = (X509Certificate) testKeystore.getCertificate(alias);
			if(currCertificate!=null)
			{
				Boolean found=false;
				for(int i=0;i<certificateList.length;i++)
				{
					if(Arrays.equals(certificateList[i].getEncoded(),currCertificate.getEncoded()))
					{
						found=true;
						break;
					}
				}
				
				assertEquals(found,true);
				count++;
			}
		}
		
		assertEquals(new Integer(certificateList.length),count);
		
		//now checking client certificates
		certificateList=server.getCertificate((InetSocketAddress)client.getLocalAddress()).getCertificateList();
		aliases=clientKeystore.aliases();
		count = 0;
		while(aliases.hasMoreElements())
		{
			String alias=aliases.nextElement();
			X509Certificate currCertificate = (X509Certificate) clientKeystore.getCertificate(alias);
			if(currCertificate!=null)
			{
				Boolean found=false;
				for(int i=0;i<certificateList.length;i++)
				{
					if(Arrays.equals(certificateList[i].getEncoded(),currCertificate.getEncoded()))
					{
						found=true;
						break;
					}
				}
				
				assertEquals(found,true);
				count++;
			}
		}
		
		assertEquals(new Integer(certificateList.length),count);
		
		//verifying that all handshake messages received
		assertEquals(server.handshakeMessagesReceived(MessageType.CLIENT_HELLO),new Integer(4));
		assertEquals(server.handshakeMessagesReceived(MessageType.CERTIFICATE),new Integer(2));
		assertEquals(server.handshakeMessagesReceived(MessageType.CLIENT_KEY_EXCHANGE),new Integer(2));
		assertEquals(server.handshakeMessagesReceived(MessageType.CERTIFICATE_VERIFY),new Integer(2));
		assertEquals(server.handshakeMessagesReceived(MessageType.FINISHED),new Integer(2));
		
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_HELLO),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.CERTIFICATE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_KEY_EXCHANGE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.CERTIFICATE_REQUEST),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.SERVER_HELLO_DONE),new Integer(1));
		assertEquals(client.handshakeMessagesReceived(MessageType.FINISHED),new Integer(1));
		
		//verifying messages itself
		assertEquals(server.getMessagesReceived(),new Integer(2));
		assertEquals(client.getMessagesReceived(),new Integer(1));
		assertEquals(server.getMessage(0),"hello message");
		assertEquals(client.getMessage(0),"server hello message");
	}
}
