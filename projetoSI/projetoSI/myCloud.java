package projetoSI;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class myCloud extends errorable {	
	
	private static DataOutputStream outStream = null;
	private static DataInputStream inStream = null;	
	private static ObjectInputStream ois = null;
	
	public static void main(String[] args) throws Exception {
		
		HashMap<String,List<String>> arguments = commandLineHandler.parse(args);
		System.out.println(arguments);
		
		if(!arguments.containsKey("-a")) {
			System.err.println("-a n�o foi fornecido.");
			System.exit(1);
		}
		String[] arg = arguments.get("-a").get(0).split(":");
		String address = arg[0];
		int port = Integer.valueOf(arg[1]);
		if(1 > port || port > 65535) {
			System.err.println("Valor de porto tem de ser maior que 1 e menor que 65535.");
			System.exit(1);
		}
		
		Socket soc = null;
		
		try {
			soc = new Socket(address,port);	
		} catch(Exception ConnectException) {
			System.err.println("ConexÃ£o recusada pelo servidor remoto.");
		}	
		
		inStream = new DataInputStream(soc.getInputStream());
		outStream = new DataOutputStream(soc.getOutputStream());
		ois = new ObjectInputStream(soc.getInputStream());
		
		ArrayList<String> user = (ArrayList<String>) arguments.get("-u");
		ArrayList<String> pwd = (ArrayList<String>) arguments.get("-p");
		ArrayList<String> enviar = (ArrayList<String>) arguments.get("-d");
		ArrayList<String> newUser = (ArrayList<String>) arguments.get("-au");
		ArrayList<String> nomeFicheirosCifrar = (ArrayList<String>) arguments.get("-c");
		ArrayList<String> nomeFicheirosEnvelope = (ArrayList<String>) arguments.get("-e");
		ArrayList<String> nomeficheirosAssinar = (ArrayList<String>) arguments.get("-s");
		ArrayList<String> nomeFicheirosAVerificar = (ArrayList<String>) arguments.get("-g");
		
		String command = null;
		for(String key:arguments.keySet()) {
			if(key.equals("-c") || key.equals("-e") || key.equals("-s") || key.equals("-g") || key.equals("-au")) {
				command = key;
			}
		}
		
		System.out.println("---------------------------------------------------------");
		
		outStream.writeUTF(command);
		
		if(command.equals("-au")) {
			
			//-------------------------------------------------------------------------
			// Comando -au
			//-------------------------------------------------------------------------
			
			if(command.equals("-au")) {
				
				outStream.writeUTF(newUser.get(0) + ":" + newUser.get(1));
				
				boolean addedUser = inStream.readBoolean();
				
				if(addedUser) {
					
					outStream.writeUTF(newUser.get(2));
					
					// Enviar o tamanaho do Certificado para o servidor
			        FileInputStream fis = new FileInputStream(newUser.get(2));
			        long fileSize = fis.getChannel().size();
			        outStream.writeInt((int) fileSize);
			        outStream.flush();
			        
			        // Enviar o certificado para o servidor
			        byte[] buffer = new byte[4096];
			        int bytesRead = 0;
			        int totalBytesRead = 0;
			        while (totalBytesRead < fileSize) {
			            bytesRead = fis.read(buffer);
			            outStream.write(buffer, 0, bytesRead);
			            totalBytesRead += bytesRead;
			        }
			        outStream.flush();
			        fis.close();
			        
			        System.out.println("O utilizador " + newUser.get(0) + " foi criado");
					
				} else {
					System.out.println("O utilizador " + newUser.get(0) + " já existe");
				}
				
			}
			
		} else {
		
			if(pwd.size() < 1) {
				error("Password deve ser fornecida pelo utilizador");
			} else {
				
				outStream.writeUTF(user.get(0)+":"+pwd.get(0));
				
				boolean auth = inStream.readBoolean();
				
				if(auth) {
					
					//-------------------------------------------------------------------------
					// Comando -c
					//-------------------------------------------------------------------------
					
			   		if(command.equals("-c")) {
			   			
			   			boolean getCertificate = false;
			   			boolean dCifrar = false;
			   			
			   			if(!arguments.containsKey("-d")) {
			   				outStream.writeUTF("N");
			   			} else {
			   				if(new File(enviar.get(0)+".cer").exists()) {
			   					outStream.writeUTF("CC:" + enviar.get(0));
			   					dCifrar = true;
			   				} else {
			   					outStream.writeUTF("NC:" + enviar.get(0));
			   					getCertificate = true;
			   					System.out.println("Ceritificado " + enviar.get(0) + ".cer não existe. Pedindo o certificado ao servidor...");
			   				}
			   			}
						
			   			if(getCertificate) {
			   				
			   				// Receber o tamanho do Certificado 
					        int fileSize = inStream.readInt();
					        
					        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
					        int bytesRead;
					        byte[] buffer = new byte[fileSize];
					        FileOutputStream fos = new FileOutputStream(enviar.get(0) + ".cer");
					        long bytesWritten = 0;
					        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
					            fos.write(buffer, 0, bytesRead);
					            bytesWritten += bytesRead;
					        }
					        fos.close();
					        System.out.println("Certificado Recebido: " + enviar.get(0) + ".cer");
					        
			   			} else {
			   			
							// Envia numero de ficheiros
							outStream.writeInt(nomeFicheirosCifrar.size());
							
							for(String ficheiro:nomeFicheirosCifrar) {
								
								// Envia o nome do ficheiro
								outStream.writeUTF(ficheiro);
								
							}
							
							for(int x = 0; nomeFicheirosCifrar.size()>x; x++) {
											
								File fI = new File(nomeFicheirosCifrar.get(x));
								
								if(!fI.exists() || fI.isDirectory()) {
									
									System.err.println(nomeFicheirosCifrar.get(x) + " n�o existe localmente ou � uma diretoria");
									outStream.writeBoolean(true);
									
								} else {
									
									outStream.writeBoolean(false);
									
									// Criar um chave AES
									KeyGenerator kg = KeyGenerator.getInstance("AES");
								    kg.init(128);
								    SecretKey key = kg.generateKey();
								    
								    Key publicKey = null;
								    
								    if(dCifrar) {
								    
									    // Obter a Chave publica do certificado
									    FileInputStream kfile = new FileInputStream(enviar.get(0) + ".cer");
									    CertificateFactory cf = CertificateFactory.getInstance("X.509");
									    Certificate cert = cf.generateCertificate(kfile);
									    publicKey = cert.getPublicKey();
									    
								    } else {
								    	
								    	// Obter a Chave publica da keystore
									    FileInputStream kfile = new FileInputStream(user.get(0) + ".keystore");
									    KeyStore kstore = KeyStore.getInstance("PKCS12");
									    kstore.load(kfile, user.get(0).toCharArray()); // password
									    Certificate cert = kstore.getCertificate(user.get(0));
									    publicKey = cert.getPublicKey();
								    	
								    }
								    
								    // Cifrar a Chave AES com a chave publica obtida da keystore
								    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
								    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
								    byte[] encryptedAesKey = cipher.doFinal(key.getEncoded());
								    
								    // Cifrar o ficheiro usando a chave AES
								    Cipher c = Cipher.getInstance("AES");
								    c.init(Cipher.ENCRYPT_MODE, key);
									
									// Cria Ficheiro da chave secreta
									FileOutputStream kos;
									String nomeFicheiro = nomeFicheirosCifrar.get(x);
									kos = new FileOutputStream(nomeFicheiro + ".chave_secretaC");
								    kos.write(encryptedAesKey);
								
								    // Cifra o ficheiro em causa
								    FileInputStream fis;
								    FileOutputStream fos;
								    CipherOutputStream cos;
								    fis = new FileInputStream(nomeFicheiro);	
								    fos = new FileOutputStream(nomeFicheiro + ".cifradoC");
								    cos = new CipherOutputStream(fos, c);
								    byte[] b = new byte[16];  
								    int i = fis.read(b);
								    while (i != -1) {
								        cos.write(b, 0, i);
								        i = fis.read(b);
								    }
								    cos.close();
								    fis.close();
								    kos.close();
								    
								    // Enviar o tamanaho do ficheiro para o servidor
							        FileInputStream fis2 = new FileInputStream(nomeFicheiro + ".cifradoC");
							        long fileSize = fis2.getChannel().size();
							        outStream.writeInt((int) fileSize);
							        outStream.flush();
							        
							        // Enviar o Ficheiro para o servidor
							        byte[] buffer = new byte[4096];
							        int bytesRead = 0;
							        int totalBytesRead = 0;
							        while (totalBytesRead < fileSize) {
							            bytesRead = fis2.read(buffer);
							            outStream.write(buffer, 0, bytesRead);
							            totalBytesRead += bytesRead;
							        }
							        outStream.flush();
							        fis2.close();
							        
							        System.out.println("Ficheiro "+ nomeFicheiro + ".cifrado enviado para o servidor!");
							        
								    // Enviar o tamanaho do ficheiro para o servidor
							        FileInputStream fisK = new FileInputStream(nomeFicheiro + ".chave_secretaC");
							        long fileSizeK = fisK.getChannel().size();
							        outStream.writeInt((int) fileSizeK);
							        outStream.flush();
							        
							        // Enviar o Ficheiro para o servidor
							        byte[] bufferK = new byte[4096];
							        int bytesReadK = 0;
							        int totalBytesReadK = 0;
							        while (totalBytesReadK < fileSizeK) {
							        	bytesReadK = fisK.read(bufferK);
							            outStream.write(bufferK, 0, bytesReadK);
							            totalBytesReadK += bytesReadK;
							        }
							        outStream.flush();
							        fisK.close();
							        
							        System.out.println("Ficheiro "+ nomeFicheiro + ".chave_secreta enviado para o servidor!");
							        
							        // Apaga os ficheiros criados localmente
							        File f = new File(nomeFicheiro + ".cifradoC");
							        File fK = new File(nomeFicheiro + ".chave_secretaC");
							        f.delete();
							        fK.delete();
									
								}
							
				   			}
							
			   			}
					
					outStream.flush();
					soc.close();
					
			 		}
					
					//-------------------------------------------------------------------------
					// Comando -s
					//-------------------------------------------------------------------------
						
			   		if(command.equals("-s")) {
			   			
			   			boolean getCertificate = false;
			   			
			   			if(!arguments.containsKey("-d")) {
			   				outStream.writeUTF("N");
			   			} else {
			   				if(new File(enviar.get(0)+".cer").exists()) {
			   					outStream.writeUTF("CC:" + enviar.get(0));
			   				} else {
			   					outStream.writeUTF("NC:" + enviar.get(0));
			   					getCertificate = true;
			   					System.out.println("Ceritificado " + enviar.get(0) + ".cer não existe. Pedindo o certificado ao servidor...");
			   				}
			   			}
						
						
			   			if(getCertificate) {
			   				
			   				// Receber o tamanho do Certificado 
					        int fileSize = inStream.readInt();
					        
					        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
					        int bytesRead;
					        byte[] buffer = new byte[fileSize];
					        FileOutputStream fos = new FileOutputStream(enviar.get(0) + ".cer");
					        long bytesWritten = 0;
					        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
					            fos.write(buffer, 0, bytesRead);
					            bytesWritten += bytesRead;
					        }
					        fos.close();
					        System.out.println("Certificado Recebido: " + enviar.get(0) + ".cer");
					        
			   			} else {
			   			
						
							outStream.writeInt(nomeficheirosAssinar.size());
							
							for(String ficheiro:nomeficheirosAssinar) {
								
								outStream.writeUTF(ficheiro);
								
							}
							
							
							for(int x = 0; nomeficheirosAssinar.size()>x; x++) {
								
								File fI = new File(nomeficheirosAssinar.get(x));
									
								if(!fI.exists() || fI.isDirectory()) {
									
									System.err.println(nomeficheirosAssinar.get(x) + " n�o existe localmente ou � uma diretoria");
									outStream.writeBoolean(true);
									
								} else {
									
									outStream.writeBoolean(false);
								
									FileInputStream kfile = new FileInputStream(user.get(0)+ ".keystore");
								    KeyStore kstore = KeyStore.getInstance("PKCS12");
								    kstore.load(kfile, user.get(0).toCharArray()); // password
									Key myPrivateKey = kstore.getKey(user.get(0), user.get(0).toCharArray());
									
									String nomeFicheiro = nomeficheirosAssinar.get(x);
											
									FileInputStream file = new FileInputStream(nomeFicheiro);
									byte [] buf = new byte[16];
									Signature s = Signature.getInstance("SHA256withRSA");
									s.initSign((PrivateKey) myPrivateKey);
									int n;
									while ((n=file.read(buf))!= -1) {
										s.update(buf, 0, n);
							
									}
									FileOutputStream fileAssinatura = new FileOutputStream(nomeFicheiro + ".assinaturaC");
									fileAssinatura.write(s.sign());
									fileAssinatura.close();
									file.close();
									
									//Enviar tamanho do ficheiro para o servidor
									FileInputStream fis = new FileInputStream(nomeFicheiro + ".assinaturaC");
							        long fileSize = fis.getChannel().size();
							        outStream.writeLong(fileSize);
							        outStream.flush();
						
							        // Enviar o Ficheiro para o servidor
							        byte[] buffer = new byte[4096];
							        int bytesRead = 0;
							        int totalBytesRead = 0;
							        while (totalBytesRead < fileSize) {
							            bytesRead = fis.read(buffer);
							            outStream.write(buffer, 0, bytesRead);
							            totalBytesRead += bytesRead;
							        }
							        outStream.flush();
							        fis.close();
							        
							        System.out.println("Ficheiro "+ nomeFicheiro + ".assinatura enviado para o servidor!");
							        
							        // Enviar o tamanaho do ficheiro para o servidor
							        FileInputStream fis2 = new FileInputStream(nomeFicheiro);
							        long fileSize2 = fis2.getChannel().size();
							        outStream.writeLong(fileSize2);
							        outStream.flush();
							        
							        
							        // Enviar o Ficheiro para o servidor
							        byte[] buffer2= new byte[4096];
							        int bytesRead2 = 0;
							        int totalBytesRead2 = 0;
							        while (totalBytesRead2 < fileSize2) {
							        	bytesRead2 = fis2.read(buffer2);
							            outStream.write(buffer2, 0, bytesRead2);
							            totalBytesRead2 += bytesRead2;
							        }
							        outStream.flush();
							        
							        System.out.println("Ficheiro "+ nomeFicheiro + ".assinado enviado para o servidor!");  
							        
								    fis2.close();
								    
								    // Apaga os ficheiros criados localmente
							        File f = new File(nomeFicheiro + ".assinaturaC");
							        f.delete();
							        
								}
									
							}
							
			   			}
						
					}
				
					//-------------------------------------------------------------------------
					// Comando -e
					//-------------------------------------------------------------------------
					
			   		if(command.equals("-e")) {
			   			
			   			boolean getCertificate = false;
			   			boolean dCifrar = false;
			   			
			   			if(!arguments.containsKey("-d")) {
			   				outStream.writeUTF("N");
			   			} else {
			   				if(new File(enviar.get(0)+".cer").exists()) {
			   					outStream.writeUTF("CC:" + enviar.get(0));
			   					dCifrar = true;
			   				} else {
			   					outStream.writeUTF("NC:" + enviar.get(0));
			   					getCertificate = true;
			   					System.out.println("Ceritificado " + enviar.get(0) + ".cer não existe. Pedindo o certificado ao servidor...");
			   				}
			   			}
						
						
			   			if(getCertificate) {
			   				
			   				// Receber o tamanho do Certificado 
					        int fileSize = inStream.readInt();
					        
					        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
					        int bytesRead;
					        byte[] buffer = new byte[fileSize];
					        FileOutputStream fos = new FileOutputStream(enviar.get(0) + ".cer");
					        long bytesWritten = 0;
					        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
					            fos.write(buffer, 0, bytesRead);
					            bytesWritten += bytesRead;
					        }
					        fos.close();
					        System.out.println("Certificado Recebido: " + enviar.get(0) + ".cer");
					        
			   			} else {
			   			
							outStream.writeInt(nomeFicheirosEnvelope.size());
							
							for(String ficheiro:nomeFicheirosEnvelope) {
								
								outStream.writeUTF(ficheiro);
								
							}
							
							for(int x = 0; nomeFicheirosEnvelope.size()>x; x++) {
								
								File fI = new File(nomeFicheirosEnvelope.get(x));
								
								if(!fI.exists() || fI.isDirectory()) {
									
									System.err.println(nomeFicheirosEnvelope.get(x) + " nï¿½o existe localmente ou ï¿½ uma diretoria");
									outStream.writeBoolean(true);
									
								} else {
								
									outStream.writeBoolean(false);
									// Criar um chave AES
									KeyGenerator kg = KeyGenerator.getInstance("AES");
								    kg.init(128);
								    SecretKey key = kg.generateKey();
								    
								    Key publicKey = null;
								    KeyStore kstore = null;
								    
								    if(dCifrar) {
								    
									    // Obter a Chave publica da keystore
									    FileInputStream kfile = new FileInputStream(enviar.get(0) + ".cer");
									    CertificateFactory cf = CertificateFactory.getInstance("X.509");
									    Certificate cert = cf.generateCertificate(kfile);
									    publicKey = cert.getPublicKey();
									    
								    } else {
								    	
								    	// Obter a Chave publica da keystore
									    FileInputStream kfile = new FileInputStream(user.get(0) + ".keystore");
									    kstore = KeyStore.getInstance("PKCS12");
									    kstore.load(kfile, user.get(0).toCharArray()); // password
									    Certificate cert = kstore.getCertificate(user.get(0));
									    publicKey = cert.getPublicKey();
								    	
								    }
								    
								    // Cifrar a Chave AES com a chave pï¿½blica obtida da keystore
								    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
								    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
								    byte[] encryptedAesKey = cipher.doFinal(key.getEncoded());
								    
								    // Cifrar o ficheiro usando a chave AES
								    Cipher c = Cipher.getInstance("AES");
								    c.init(Cipher.ENCRYPT_MODE, key);
									
								    FileInputStream fis;
								    FileOutputStream fos;
								    CipherOutputStream cos;	   
										
									String nomeFicheiro = nomeFicheirosEnvelope.get(x);
								    fis = new FileInputStream(nomeFicheiro);
								    fos = new FileOutputStream(nomeFicheiro + ".seguroC");
						
								    cos = new CipherOutputStream(fos, c);
								    
								    byte[] b = new byte[16];  
								    int i = fis.read(b);
								    while (i != -1) {
								        cos.write(b, 0, i);
								        i = fis.read(b);
								    }
								    
								    cos.close();
								    fis.close();
								    fos.close();
								    
								    // Enviar o tamanaho do ficheiro para o servidor
							        FileInputStream fis2 = new FileInputStream(nomeFicheiro + ".seguroC");
							        
							        long fileSize = fis2.getChannel().size();
							        
							        outStream.writeInt((int) fileSize);
							        outStream.flush();
						
							        // Enviar o Ficheiro para o servidor
							        byte[] buffer = new byte[4096];
							        int bytesRead = 0;
							        int totalBytesRead = 0;
							        while (totalBytesRead < fileSize) {
							            bytesRead = fis2.read(buffer);
							            outStream.write(buffer, 0, bytesRead);
							            totalBytesRead += bytesRead;
							        }
							        outStream.flush();
							        
							        System.out.println("Ficheiro "+ nomeFicheiro + ".seguro enviado para o servidor!");
							        
								    fis2.close();
								    
								    //Assinatura
							            
								    FileInputStream kfile = new FileInputStream(user.get(0) + ".keystore");
								    kstore = KeyStore.getInstance("PKCS12");
								    kstore.load(kfile, user.get(0).toCharArray()); // password
									Key myPrivateKey = kstore.getKey(user.get(0), user.get(0).toCharArray());
										
									FileInputStream file = new FileInputStream(nomeFicheiro);
									byte [] buf = new byte[16];
									Signature s = Signature.getInstance("SHA256withRSA");
									s.initSign((PrivateKey) myPrivateKey);
									int n;
									while ((n=file.read(buf))!= -1) {
										s.update(buf, 0, n);
							
									}
									FileOutputStream fileAssinatura = new FileOutputStream(nomeFicheiro + ".assinaturaC");
									fileAssinatura.write(s.sign());
									fileAssinatura.close();
									file.close();
									
									FileInputStream fis3 = new FileInputStream(nomeFicheiro + ".assinaturaC");
							        
							        long fileSize2 = fis3.getChannel().size();
							        
							        outStream.writeInt((int) fileSize2);
							        outStream.flush();
							
							        // Enviar o Ficheiro para o servidor
							        byte[] buffer2 = new byte[4096];
							        int bytesRead2 = 0;
							        int totalBytesRead2 = 0;
							        while (totalBytesRead2 < fileSize2) {
							            bytesRead2 = fis3.read(buffer2);
							            outStream.write(buffer2, 0, bytesRead2);
							            totalBytesRead2 += bytesRead2;
							        }
							        outStream.flush();
							        
							        System.out.println("Ficheiro "+ nomeFicheiro + ".assinatura enviado para o servidor!");
							        
								    fis3.close();
								    
								    // Chave-secreta
									FileOutputStream kos = new FileOutputStream(nomeFicheiro + ".chave_secretaC");
								    kos.write(encryptedAesKey);
								    kos.close();
								    
							        FileInputStream fisS = new FileInputStream(nomeFicheiro + ".chave_secretaC");
							        long fileSizeS = fisS.getChannel().size();
							        outStream.writeInt((int) fileSizeS);
							        outStream.flush();
							        
							        // Enviar o Ficheiro para o servidor
							        byte[] bufferS = new byte[4096];
							        int bytesReadS = 0;
							        int totalBytesReadS = 0;
							        while (totalBytesReadS < fileSizeS) {
							        	bytesReadS = fisS.read(bufferS);
							            outStream.write(bufferS, 0, bytesReadS);
							            totalBytesReadS += bytesReadS;
							        }
							        outStream.flush();
							        fisS.close();
							        
							        System.out.println("Ficheiro "+ nomeFicheiro + ".chave_secreta enviado para o servidor!");
							        
							        
							        File f = new File(nomeFicheiro + ".assinaturaC");
							        f.delete();
							        File f2 = new File(nomeFicheiro + ".chave_secretaC");
							        f2.delete();
							        File f3 = new File(nomeFicheiro + ".seguroC");
							        f3.delete();
							        
								}
							}
						
			   			}
					
					soc.close();
						
					
					}
					
					//-------------------------------------------------------------------------
					// Comando -g
					//-------------------------------------------------------------------------
						
					if(command.equals("-g")) {
						
						boolean getCertificate = false;
						String extension = "";
						
						for(String ficheiro:nomeFicheirosAVerificar) {
							
							// && ficheiro.endsWith("." + user.get(0))
							if(ficheiro.contains(".cifrado")) {
								continue;
							} else if(ficheiro.contains(".assinado")) {
								String[] segments = ficheiro.split("\\.");
								extension = segments[segments.length - 1];
								if(new File(extension+".cer").exists()) {
									continue;
								} else {
									getCertificate = true;
									System.out.println("Ceritificado " + extension + ".cer não existe. Pedindo o certificado ao servidor...");
								}
							} else {
								
								error("Não é possível realizar esta tarefa");
								
							}
							
						}
						
						if(getCertificate) {
							outStream.writeUTF("NC:" + extension);
						} else {
							outStream.writeUTF("N");
						}
						
						if(getCertificate) {
			   				
			   				// Receber o tamanho do Certificado 
					        int fileSize = inStream.readInt();
					        
					        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
					        int bytesRead;
					        byte[] buffer = new byte[fileSize];
					        FileOutputStream fos = new FileOutputStream(extension + ".cer");
					        long bytesWritten = 0;
					        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
					            fos.write(buffer, 0, bytesRead);
					            bytesWritten += bytesRead;
					        }
					        fos.close();
					        System.out.println("Certificado Recebido: " + extension + ".cer");
					        
			   			} else {
						
							outStream.writeInt(nomeFicheirosAVerificar.size());
							
							for(String ficheiro:nomeFicheirosAVerificar) {
								
								outStream.writeUTF(ficheiro);
								
							}
							
							for(int x = 0; nomeFicheirosAVerificar.size()>x; x++) {
								
								File fI = new File(nomeFicheirosAVerificar.get(x));
									
								if(fI.exists()) {
									
									System.err.println(nomeFicheirosAVerificar.get(x) + " já existe localmente");
									outStream.writeBoolean(true);
									
								} else {
									
									outStream.writeBoolean(false);
									
									Boolean nExiste = inStream.readBoolean();
									
									if (nExiste) {
										
										System.err.println(nomeFicheirosAVerificar.get(x) + " não existe no servidor");
										continue;
										
									} else {
										
										String nomeFicheiro = nomeFicheirosAVerificar.get(x);
										
										if(nomeFicheiro.contains(".cifrado")) {
											
											 // -------- Receber ficheiro da .cifrado --------
											
											// Receber o tamanho do ficheiro 
									        int fileSize = inStream.readInt();
									        
									        // Ler o conteudo do ficheiro e criar um ficheiro no cliente
									        int bytesRead;
									        byte[] buffer = new byte[fileSize];
									        FileOutputStream fos = new FileOutputStream(nomeFicheiro + ".cifradoC");
									        long bytesWritten = 0;
									        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
									            fos.write(buffer, 0, bytesRead);
									            bytesWritten += bytesRead;
									        }
									        fos.close();
									        System.out.println("Ficheiro Guardado: " + nomeFicheiro + ".cifradoC");
									        
									        // -------- Receber ficheiro .chave_secreta --------
									        
									        // Receber o tamanho do ficheiro 
									        int fileSizeK = inStream.readInt();
									        
									        // Ler o conteudo do ficheiro e criar um ficheiro no cliente
									        int bytesReadK;
									        byte[] bufferK = new byte[fileSizeK];
									        FileOutputStream kos = new FileOutputStream(nomeFicheiro + ".chave_secretaC");
									        long bytesWrittenK = 0;
									        while (bytesWrittenK < fileSizeK && (bytesReadK = inStream.read(bufferK, 0, (int) Math.min(bufferK.length, fileSizeK - bytesWrittenK))) != -1) {
									        	kos.write(bufferK, 0, bytesReadK);
									            bytesWrittenK += bytesReadK;
									        }
									        kos.close();
									        System.out.println("Ficheiro da chave Guardado: " + nomeFicheiro + ".chave_secretaC");
											
									        // ---------------- Decifrar ----------------
									        
									        //carregar a keystore com a chave pública RSA
									        FileInputStream kfile = new FileInputStream(user.get(0) + ".keystore");
									        KeyStore kstore = KeyStore.getInstance("PKCS12");
									        char[] password = user.get(0).toCharArray();
									        kstore.load(kfile, password);
									        Certificate cert = kstore.getCertificate(user.get(0));
									        PublicKey publicKey = cert.getPublicKey();
									        
									        //ler a chave cifrada com a chave pública RSA
									        FileInputStream keyIn = new FileInputStream(nomeFicheiro + ".chave_secretaC");
									        byte[] encryptedKey = new byte[keyIn.available()];
									        keyIn.read(encryptedKey);
									        keyIn.close();
									        
									        //decifrar a chave AES com a chave privada RSA
									        Cipher cipher = Cipher.getInstance("RSA");
									        cipher.init(Cipher.DECRYPT_MODE, (PrivateKey) kstore.getKey(user.get(0), password));
									        byte[] decryptedKey = cipher.doFinal(encryptedKey);
									        
									        //preparar o cipher para decifrar os dados
									        SecretKeySpec keySpec = new SecretKeySpec(decryptedKey, "AES");
									        Cipher c = Cipher.getInstance("AES");
									        c.init(Cipher.DECRYPT_MODE, keySpec);
									        
			
									        //ler os dados cifrados e decifra-os
									        FileInputStream fis = new FileInputStream(nomeFicheiro + ".cifradoC");
									        CipherInputStream cis = new CipherInputStream(fis, c);
			
									        String nomeDecifrado = nomeFicheiro.replace(".cifrado", ".decifrado");
									        
									        FileOutputStream fos2 = new FileOutputStream(nomeDecifrado);
									       
									        byte[] b2 = new byte[16];  
									        int i2 = cis.read(b2);
									        while (i2 != -1) {
									        	fos2.write(b2, 0, i2);
									            i2 = cis.read(b2);
									        }
									        fos2.close();
									        cis.close();
									        
									        System.out.println("--------------------------------------------------------");
									        System.out.println("O conteudo do ficheiro " + nomeFicheiro + " encontra-se decifrado em " + nomeDecifrado);
									        System.out.println("--------------------------------------------------------");
			
									        
									        // Apaga os ficheiros criados localmente
									        File f = new File(nomeFicheiro + ".cifradoC");
									        File fK = new File(nomeFicheiro + ".chave_secretaC");
									        f.delete();
									        fK.delete();
											
										} else {
											
											// -------- Receber ficheiro .assinado --------
											
											// Receber o tamanho do ficheiro 
									        int fileSize = inStream.readInt();
									        
									        // Ler o conteudo do ficheiro e criar um ficheiro no cliente
									        int bytesRead;
									        byte[] buffer = new byte[fileSize];
									        FileOutputStream fos = new FileOutputStream(nomeFicheiro + ".assinadoC");
									        long bytesWritten = 0;
									        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
									            fos.write(buffer, 0, bytesRead);
									            bytesWritten += bytesRead;
									        }
									        fos.close();
									        System.out.println("Ficheiro Guardado: " + nomeFicheiro + ".assinadoC");
									        
									        // -------- Receber conteudo .assinatura --------
									        
									        FileInputStream fis = new FileInputStream(nomeFicheiro + ".assinadoC");
									        byte[] conteudoOriginal = fis.readAllBytes();
									        
									        byte[] conteudoAssinatura = (byte[]) ois.readObject();
									        
									        // Obter a Chave publica da keystore
										    FileInputStream kfile = new FileInputStream(extension + ".cer");
										    CertificateFactory cf = CertificateFactory.getInstance("X.509");
										    Certificate cert = cf.generateCertificate(kfile);
										    PublicKey publicKey = cert.getPublicKey();
									        
									        Signature s = Signature.getInstance("SHA256withRSA");
									        s.initVerify(publicKey);
			
									        s.update(conteudoOriginal);
									        
									        boolean resultadoVerificacao = s.verify(conteudoAssinatura);
			
									        if(resultadoVerificacao) {
									        	
									        	System.out.println("--------------------------------------------------------");
									        	System.out.println("Resultado da verifica��o da assinatura: " + resultadoVerificacao);
									        	System.out.println("--------------------------------------------------------");
									        	
									        } else {
									        	
									        	System.out.println("--------------------------------------------------------");
									        	System.out.println("Resultado da verifica��o da assinatura: " + resultadoVerificacao);
									        	System.out.println("--------------------------------------------------------");
									        	
									        }
									        
									        fis.close();
									        
									        // Apaga os ficheiros criados localmente
									        File f = new File(nomeFicheiro + ".assinadoC");
									        f.delete();
									       
										}
			
									}
									
								}
								
							}
							
						}
						
					}
					
				} else {
					
					System.err.println("Utilizador não Autenticado. Parâmetros não existem ou estão errados");
					
				}
				
			}
			
		}
		
}
}