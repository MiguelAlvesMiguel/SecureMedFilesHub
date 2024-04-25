package projetoSI;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class myCloudServer {
	
	DataInputStream inStream = null;
	DataOutputStream outStream = null;
	ObjectOutputStream oos = null;
	
	private static Integer port;
	private Socket sock;
	private static userFile pwfile = null;
	
	public static void main(String[] args) throws Exception {
		try {
			port = Integer.parseInt(args[0]); //porta como argumento
		}catch(NumberFormatException e){
			System.err.print("Valor de porto inválido.");
		}
		if(1 > port || port > 65535) {
			throw new Exception("Valor de porto tem de ser maior que 1 e menor que 65535.");
		}
		myCloudServer server = new myCloudServer();
		pwfile = userFile.getFile("passwords");
		directoryHandlerServer.createCertDir();
		
		server.serve();
	}
	
	private void serve() throws Exception {
		
	    ServerSocket socket = new ServerSocket(port);
		
		while(true) {
			
			Socket inputSocket = socket.accept();
			ServerThread newThread = new ServerThread(inputSocket);
			newThread.start();
			
		}	
	}
	
	private class ServerThread extends Thread{
		
		private Socket threadSoc = null;
		
		ServerThread(Socket inputSocket) throws IOException {
			threadSoc = inputSocket;
		}
		
		public void run() {	
		
			try {
				
				System.out.println("---------------------------------------------------------");
				inStream = new DataInputStream(threadSoc.getInputStream());
				
				outStream = new DataOutputStream(threadSoc.getOutputStream());
				oos = new ObjectOutputStream(threadSoc.getOutputStream());
				
				String command = inStream.readUTF();
				
				System.out.println("Comando recebido: " + command);
				
				//-------------------------------------------------------------------------
				// Comando -au
				//-------------------------------------------------------------------------
				
				if(command.equals("-au")) {
					
					String newUserUnfiltered = inStream.readUTF();
					
					String[] newUser = newUserUnfiltered.split(":");
					String newUsername = newUser[0];
					String newPassword = newUser[1];
					
					boolean addedUser = pwfile.newUser(newUsername, newPassword);
					outStream.writeBoolean(addedUser);
				
					
					if(addedUser) {
						
						String nomeCert = inStream.readUTF();
						
						// Receber o tamanho do ficheiro 
				        int fileSize = inStream.readInt();
				        
				        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
				        int bytesRead;
				        byte[] buffer = new byte[fileSize];
				        FileOutputStream fos = new FileOutputStream("Certificados/" + nomeCert);
				        long bytesWritten = 0;
				        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
				            fos.write(buffer, 0, bytesRead);
				            bytesWritten += bytesRead;
				        }
				        fos.close();
				        System.out.println("Certificado Guardado: " + nomeCert);
						
						Boolean dirCreated = directoryHandlerServer.createDir(newUsername);
						
						if(dirCreated) {
							
							System.out.println("Diretoria criado com sucesso");
							
						} else {
							System.out.println("Diretoria j� existe");
						}
					}
					
					
				} else {
					
					String[] user = inStream.readUTF().split(":");
					
					String username = user[0];
					String password = user[1];
					
					boolean auth = false;
					
					/*
					
					//localização do mac, ver isso
					
					File macFile = new File("password.mac");
					
					if (!macFile.exists()) {
						System.out.println("Ficheiro MAC nao encontrado. Pretende calcular agora o MAC?(s/n)");
						String res = new Scanner(System.in).next();
						if (res.equals("s")) {
							
							criarMac(password);
							
							System.out.println("Ficheiro MAC criado com sucesso!");
							auth = pwfile.authUser(username, password);
						} 
					} else {
						if (!verificaMac(password)) {
							System.out.println("MAC incorreta!");
						}
						else {
							auth = pwfile.authUser(username, password);
						}
					}
					*/
				
					auth = pwfile.authUser(username, password);
					outStream.writeBoolean(auth);
					
					if(auth) {
					
						//-------------------------------------------------------------------------
						// Comando -c
						//-------------------------------------------------------------------------
						
						if(command.equals("-c")) {
							
							String dUnfiltered = inStream.readUTF();
							
							String[] dInfo = dUnfiltered.split(":");
							
							String flag = null;
							String dParam = null;
							if(dInfo.length>1) {
								flag = dInfo[0];
								dParam = dInfo[1];
							} else {
								flag = dInfo[0];
							}
							
							if(flag.equals("NC")) {
								
								FileInputStream fis1 = new FileInputStream("Certificados/" + dParam + ".cer");
								
								//Enviar tamanho do certificado para o cliente
								long fileSize = fis1.getChannel().size();
						        
						        outStream.writeInt((int) fileSize);
						        outStream.flush();
						        
						        //Enviar o Ficheiro para o servidor
						        byte[] buffer = new byte[4096];
						        int bytesRead = 0;
						        int totalBytesRead = 0;
						        while (totalBytesRead < fileSize) {
						            bytesRead = fis1.read(buffer);
						            outStream.write(buffer, 0, bytesRead);
						            totalBytesRead += bytesRead;
						        }
						        outStream.flush();
						        
						        System.out.println("Ficheiro "+ dParam + ".cer enviado para o Cliente!");
						        
						        fis1.close();
						        
							} else {
							
								int numFicheiros = inStream.readInt();
								
								ArrayList<String> nomesFicheiros = new ArrayList<String>();
								
								for(int i = 0; i < numFicheiros; i++) {
									
									String nomeFicheiro = inStream.readUTF();
									nomesFicheiros.add(nomeFicheiro);
									
								}
								
								boolean stop = false;
								
								for(int i = 0; i < numFicheiros; i++) {
								
									stop = inStream.readBoolean();
									
									if(stop) {
										
										continue;
										
									} else {
										
										String nomeFicheiroI = nomesFicheiros.get(i);
										FileOutputStream fos = null;
										FileOutputStream kos = null;
										
										// Receber o tamanho do ficheiro 
								        int fileSize = inStream.readInt();
								        
								        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
								        int bytesRead;
								        byte[] buffer = new byte[fileSize];
								        if(flag.contentEquals("N")) {
								        	fos = new FileOutputStream(username + "/" + nomeFicheiroI + ".cifrado." + username);
								        } else {
								        	fos = new FileOutputStream(dParam + "/" + nomeFicheiroI + ".cifrado." + username);
								        }
								        long bytesWritten = 0;
								        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
								            fos.write(buffer, 0, bytesRead);
								            bytesWritten += bytesRead;
								        }
								        fos.close();
								        System.out.println("Ficheiro Guardado: " + nomeFicheiroI + ".cifrado." + username);
								        
								        // -------- Receber ficheiro da Chave Secreta --------
								        
								        // Receber o tamanho do ficheiro 
								        int fileSizeK = inStream.readInt();
								        
								        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
								        int bytesReadK;
								        byte[] bufferK = new byte[fileSizeK];
								        if(flag.contentEquals("N")) {
								        	kos = new FileOutputStream(username + "/" + nomeFicheiroI + ".chave_secreta." + username);
								        } else {
								        	kos = new FileOutputStream(dParam + "/" + nomeFicheiroI + ".chave_secreta." + username);
								        }
								        long bytesWrittenK = 0;
								        while (bytesWrittenK < fileSizeK && (bytesReadK = inStream.read(bufferK, 0, (int) Math.min(bufferK.length, fileSizeK - bytesWrittenK))) != -1) {
								        	kos.write(bufferK, 0, bytesReadK);
								            bytesWrittenK += bytesReadK;
								        }
								        kos.close();
								        System.out.println("Ficheiro da chave Guardado: " + nomeFicheiroI + ".chave_secreta." + username);
										
									}
									
				                }
							
							}
		
						}
						
						//-------------------------------------------------------------------------
						// Comando -s
						//-------------------------------------------------------------------------
						
						if(command.equals("-s")) {
							
							String dUnfiltered = inStream.readUTF();
							
							String[] dInfo = dUnfiltered.split(":");
							
							String flag = null;
							String dParam = null;
							if(dInfo.length>1) {
								flag = dInfo[0];
								dParam = dInfo[1];
							} else {
								flag = dInfo[0];
							}
							
							if(flag.equals("NC")) {
								
								FileInputStream fis1 = new FileInputStream("Certificados/" + dParam + ".cer");
								
								//Enviar tamanho do certificado para o cliente
								long fileSize = fis1.getChannel().size();
						        
						        outStream.writeInt((int) fileSize);
						        outStream.flush();
						        
						        //Enviar o Ficheiro para o servidor
						        byte[] buffer = new byte[4096];
						        int bytesRead = 0;
						        int totalBytesRead = 0;
						        while (totalBytesRead < fileSize) {
						            bytesRead = fis1.read(buffer);
						            outStream.write(buffer, 0, bytesRead);
						            totalBytesRead += bytesRead;
						        }
						        outStream.flush();
						        
						        System.out.println("Ficheiro "+ dParam + ".cer enviado para o Cliente!");
						        
						        fis1.close();
						        
							} else {
							
								int numFicheiros = inStream.readInt();
								
								ArrayList<String> nomesFicheiros = new ArrayList<String>();
								
								for(int i = 0; i < numFicheiros; i++) {
									
									String nomeFicheiro = inStream.readUTF();
									nomesFicheiros.add(nomeFicheiro);
									
								}
								
								boolean stop2 = false;
								
								for(int i = 0; i < numFicheiros; i++) {
									
									stop2 = inStream.readBoolean();
									
									if(stop2) {
										
										continue;
										
									} else {
										
										FileOutputStream fos = null;
										FileOutputStream fos2 = null;
									
										String nomeFicheiroI = nomesFicheiros.get(i);
										
										// Receber o tamanho do ficheiro 
								        long fileSize = inStream.readLong();
								        
								        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
								        int bytesRead;
								        byte[] buffer = new byte[(int) fileSize];
								        if(flag.contentEquals("N")) {
								        	fos = new FileOutputStream(username + "/" + nomeFicheiroI + ".assinatura." +  username);
								        } else {
								        	fos = new FileOutputStream(dParam + "/" + nomeFicheiroI + ".assinatura." +  username);
								        }
								        long bytesWritten = 0;
								        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
								            fos.write(buffer, 0, bytesRead);
								            bytesWritten += bytesRead;
								        }
	
								        System.out.println("Ficheiro Guardado: " + nomeFicheiroI + ".assinatura." + username);
								        fos.close();
								        
								        
								        // ----------------------------------------------------
								    	
										// Receber o tamanho do ficheiro 
								        long fileSize2 = inStream.readLong();
								        
								        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
								        int bytesRead2;
								        byte[] buffer2 = new byte[(int) fileSize2];
								        if(flag.contentEquals("N")) {
								        	fos2 = new FileOutputStream(username + "/" + nomeFicheiroI + ".assinado." + username);
								        } else {
								        	fos2 = new FileOutputStream(dParam + "/" + nomeFicheiroI + ".assinado." + username);
								        }
								        long bytesWritten2 = 0;
								        while (bytesWritten2 < fileSize2 && (bytesRead2 = inStream.read(buffer2, 0, (int) Math.min(buffer2.length, fileSize2 - bytesWritten2))) != -1) {
								            fos2.write(buffer2, 0, bytesRead2);
								            bytesWritten2 += bytesRead2;
								        }
								        System.out.println("Ficheiro Guardado: " + nomeFicheiroI + ".assinado." + username);
								        fos2.close();
								        
								        
									}
							        
				                }
								
							}

						}
						
						//-------------------------------------------------------------------------
						// Comando -e
						//-------------------------------------------------------------------------
						
						if(command.equals("-e")) {
							
							String dUnfiltered = inStream.readUTF();
							
							String[] dInfo = dUnfiltered.split(":");
							
							String flag = null;
							String dParam = null;
							if(dInfo.length>1) {
								flag = dInfo[0];
								dParam = dInfo[1];
							} else {
								flag = dInfo[0];
							}
							
							if(flag.equals("NC")) {
								
								FileInputStream fis1 = new FileInputStream("Certificados/" + dParam + ".cer");
								
								//Enviar tamanho do certificado para o cliente
								long fileSize = fis1.getChannel().size();
						        
						        outStream.writeInt((int) fileSize);
						        outStream.flush();
						        
						        //Enviar o Ficheiro para o servidor
						        byte[] buffer = new byte[4096];
						        int bytesRead = 0;
						        int totalBytesRead = 0;
						        while (totalBytesRead < fileSize) {
						            bytesRead = fis1.read(buffer);
						            outStream.write(buffer, 0, bytesRead);
						            totalBytesRead += bytesRead;
						        }
						        outStream.flush();
						        
						        System.out.println("Ficheiro "+ dParam + ".cer enviado para o Cliente!");
						        
						        fis1.close();
						        
							} else {
							
								int numFicheiros = inStream.readInt();
								
								ArrayList<String> nomesFicheiros = new ArrayList<String>();
								
								for(int i = 0; i < numFicheiros; i++) {
									
									String nomeFicheiro = inStream.readUTF();
									nomesFicheiros.add(nomeFicheiro);
									
								}
								
								for(int i = 0; i < numFicheiros; i++) {
									
									boolean stop3 = inStream.readBoolean();
									
									if(stop3) {
										
										continue;
										
									} else {
										
										FileOutputStream fos = null;
										FileOutputStream fis3 = null;
										FileOutputStream fosS = null;
									
										String nomeFicheiroI = nomesFicheiros.get(i);
										
										// Receber o tamanho do ficheiro 
								        int fileSize = inStream.readInt();
								        
								        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
								        int bytesRead;
								        byte[] buffer = new byte[fileSize];
								        if(flag.contentEquals("N")) {
								        	fos = new FileOutputStream(username + "/" + nomeFicheiroI + ".seguro." + username);
								        } else {
								        	fos = new FileOutputStream(dParam + "/" + nomeFicheiroI + ".seguro." + username);
								        }
								        long bytesWritten = 0;
								        while (bytesWritten < fileSize && (bytesRead = inStream.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesWritten))) != -1) {
								            fos.write(buffer, 0, bytesRead);
								            bytesWritten += bytesRead;
								        }
								        fos.close();
								        System.out.println(fileSize);
								        System.out.println("Ficheiro Guardado: " + nomeFicheiroI + ".seguro." + username);
								        
								        
								        // -------- Receber ficheiro Assinatura --------
								        
								        // Receber o tamanho do ficheiro 
								        int fileSize2 = inStream.readInt();
								        
								        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
								        int bytesRead2;
								        byte[] buffer2 = new byte[fileSize2];
								        if(flag.contentEquals("N")) {
								        	fis3 = new FileOutputStream(username + "/" + nomeFicheiroI + ".assinatura." + username);
								        } else {
								        	fis3 = new FileOutputStream(dParam + "/" + nomeFicheiroI + ".assinatura." + username);
								        }
								        long bytesWritten2 = 0;
								        while (bytesWritten2 < fileSize2 && (bytesRead2 = inStream.read(buffer2, 0, (int) Math.min(buffer2.length, fileSize2 - bytesWritten2))) != -1) {
								        	fis3.write(buffer2, 0, bytesRead2);
								            bytesWritten2 += bytesRead2;
								        }
								        fis3.close();
								        System.out.println(fileSize2);
								        System.out.println("Ficheiro da chave Guardado: " + nomeFicheiroI + ".assinatura." + username);
								        
								     // -------- Receber ficheiro da Chave Secreta --------
								        
								        // Receber o tamanho do ficheiro 
								        int fileSizeS = inStream.readInt();
								        
								        // Ler o conteudo do ficheiro e criar um ficheiro no servidor
								        int bytesReadS;
								        byte[] bufferS = new byte[fileSizeS];
								        if(flag.contentEquals("N")) {
								        	fosS = new FileOutputStream(username + "/" + nomeFicheiroI + ".chave_secreta." + username);
								        } else {
								        	fosS = new FileOutputStream(dParam + "/" + nomeFicheiroI + ".chave_secreta." + username);
								        }
								        long bytesWrittenS = 0;
								        while (bytesWrittenS < fileSizeS && (bytesReadS = inStream.read(bufferS, 0, (int) Math.min(bufferS.length, fileSizeS - bytesWrittenS))) != -1) {
								            fosS.write(bufferS, 0, bytesReadS);
								            bytesWrittenS += bytesReadS;
								        }
								        fosS.close();
								        System.out.println(fileSizeS);
								        System.out.println("Ficheiro Guardado: " + nomeFicheiroI + ".chave_secreta." + username);
								        
									}
								        
				                }
								
							}

						}
						
						//-------------------------------------------------------------------------
						// Comando -g
						//-------------------------------------------------------------------------
						
						if(command.equals("-g")) {
							
							String dUnfiltered = inStream.readUTF();
							
							String[] certInfo = dUnfiltered.split(":");
							
							String flag = null;
							String certParam = null;
							if(certInfo.length>1) {
								flag = certInfo[0];
								certParam = certInfo[1];
							} else {
								flag = certInfo[0];
								certParam = username;
							}
							
							if(flag.equals("NC")) {
								
								FileInputStream fis1 = new FileInputStream("Certificados/" + certParam + ".cer");
								
								//Enviar tamanho do certificado para o cliente
								long fileSize = fis1.getChannel().size();
						        
						        outStream.writeInt((int) fileSize);
						        outStream.flush();
						        
						        //Enviar o Ficheiro para o servidor
						        byte[] buffer = new byte[4096];
						        int bytesRead = 0;
						        int totalBytesRead = 0;
						        while (totalBytesRead < fileSize) {
						            bytesRead = fis1.read(buffer);
						            outStream.write(buffer, 0, bytesRead);
						            totalBytesRead += bytesRead;
						        }
						        outStream.flush();
						        
						        System.out.println("Ficheiro "+ certParam + ".cer enviado para o Cliente!");
						        
						        fis1.close();
						        
							} else {
							
								int numFicheiros = inStream.readInt();
								
								ArrayList<String> nomesFicheiros = new ArrayList<String>();
								
								for(int i = 0; i < numFicheiros; i++) {
									
									String nomeFicheiro = inStream.readUTF();
									nomesFicheiros.add(nomeFicheiro);
									
								}
								
								boolean stop = false;
								
								for(int i = 0; i < numFicheiros; i++) {
									
									stop = inStream.readBoolean();
									
									if(stop) {
									
										continue;
										
									} else {
										
										File fI = new File(username + "/" + nomesFicheiros.get(i));
										
										if (!fI.exists()) {
											
											outStream.writeBoolean(true);
											continue;
											
										} else {
											
											outStream.writeBoolean(false);
											
											String nomeFicheiroI = nomesFicheiros.get(i);
											
											if(nomeFicheiroI.contains(".cifrado")) {
												
												 // -------- Envia ficheiros .cifrado para o cliente --------
												
												// Enviar o tamanaho do ficheiro para o cliente
										        FileInputStream fis2 = new FileInputStream(certParam + "/" + nomeFicheiroI);
										        long fileSize = fis2.getChannel().size();
										        outStream.writeInt((int) fileSize);
										        outStream.flush();
			
										        // Enviar o Ficheiro para o cliente
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
										        
										        System.out.println("Ficheiro" + certParam + "/" + nomeFicheiroI + " enviado para o cliente!");
										        
										        // -------- Envia ficheiros .chave_secreta para o cliente --------
										        
										        String nomeChaveSecreta = nomeFicheiroI.replace(".cifrado", ".chave_secreta");
										        
											    // Enviar o tamanaho do ficheiro para o cliente
										        FileInputStream fisK = new FileInputStream(certParam + "/" + nomeChaveSecreta);
										        long fileSizeK = fisK.getChannel().size();
										        outStream.writeInt((int) fileSizeK);
										        outStream.flush();
										        
										        // Enviar o Ficheiro para o cliente
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
										        
										        System.out.println("Ficheiro " + certParam + "/" + nomeChaveSecreta + " enviado para o cliente!");
										        
											} else {
												
												 // -------- Envia ficheiros .assinado para o cliente --------
												
												// Enviar o tamanaho do ficheiro para o cliente
										        FileInputStream fis2 = new FileInputStream(username + "/" + nomeFicheiroI);
										        long fileSize = fis2.getChannel().size();
										        outStream.writeInt((int) fileSize);
										        outStream.flush();
			
										        // Enviar o Ficheiro para o cliente
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
										        
										        System.out.println("Ficheiro" + username + "/" + nomeFicheiroI + " enviado para o cliente!");
										        
										        // -------- Envia o conteudo do ficheiro .assinatura para o cliente --------
										        
										        String nomeAssinatura = nomeFicheiroI.replace(".assinado", ".assinatura");
										        
											    // Enviar o tamanaho do ficheiro para o cliente
										        FileInputStream fisK = new FileInputStream(username + "/" + nomeAssinatura);
										        byte[] conteudoAssinatura = fisK.readAllBytes();
										        
										        oos.writeObject(conteudoAssinatura);
										        
										        fisK.close();
										        
										        System.out.println("Ficheiro" + username + "/" + nomeAssinatura + " enviado para o cliente!");
										        
											}
											
										}
										
									}
									
								}
								
							}
					
						}
							
					}
					
				}
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			
			}/* catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			*/
			
			
	
		}
		public void criarMac (String pwdAdmin) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
			byte [] pass = pwdAdmin.getBytes(); 
			SecretKey key = new SecretKeySpec(pass, "HmacSHA256"); 
			
			
			//mudar conforme a localização do ficheiro users
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream("passwords"));
			byte[] msg = bis.readAllBytes();
			
			Mac m; 
			m = Mac.getInstance("HmacSHA256"); 
			m.init(key); 
			m.update(msg);
			
			//mudar conforme onemeter o ficheiro .mac
			// onde diz Servidor é a pasta onde vai tar o ficheiro mac, só e preciso mudar nomes
			ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream("password.mac"));
			os.writeObject(msg);
			os.writeObject(m.doFinal());
			
			os.close();
			bis.close();
		}
		
		public boolean verificaMac(String pwd) throws IOException, NoSuchAlgorithmException, InvalidKeyException, ClassNotFoundException {
			byte [] pass = pwd.getBytes(); 
			SecretKey key = new SecretKeySpec(pass, "HmacSHA256"); 
			
			//mudar conforme a localização do ficheiro users
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream("passwords"));
			byte[] msg = bis.readAllBytes();
			bis.close();
			
			Mac m; 
			m = Mac.getInstance("HmacSHA256"); 
			m.init(key); 
			m.update(msg);
			
			//mudar conforme onemeter o ficheiro .mac
			// onde diz Servidor é a pasta onde vai tar o ficheiro mac, só e preciso mudar nomes
			ObjectInputStream is = new ObjectInputStream(new FileInputStream("password.mac"));
			is.readObject();
			
			return Arrays.equals(m.doFinal(), (byte[])is.readObject());
		}
		
	}
	
}
