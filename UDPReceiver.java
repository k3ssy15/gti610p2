import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;

import javax.print.attribute.standard.PrinterLocation;

/**
 * Cette classe permet la reception d'un paquet UDP sur le port de reception
 * UDP/DNS. Elle analyse le paquet et extrait le hostname
 * 
 * Il s'agit d'un Thread qui ecoute en permanance pour ne pas affecter le
 * deroulement du programme
 * 
 * @author Max
 *
 */

public class UDPReceiver extends Thread {
	/**
	 * Les champs d'un Packet UDP 
	 * --------------------------
	 * En-tete (12 octects) 
	 * Question : l'adresse demande 
	 * Reponse : l'adresse IP
	 * Autorite :
	 * info sur le serveur d'autorite 
	 * Additionnel : information supplementaire
	 */

	/**
	 * Definition de l'En-tete d'un Packet UDP
	 * --------------------------------------- 
	 * Identifiant Parametres 
	 * QDcount
	 * Ancount
	 * NScount 
	 * ARcount
	 * 
	 * L'identifiant est un entier permettant d'identifier la requete. 
	 * parametres contient les champs suivant : 
	 * 		QR (1 bit) : indique si le message est une question (0) ou une reponse (1). 
	 * 		OPCODE (4 bits) : type de la requete (0000 pour une requete simple). 
	 * 		AA (1 bit) : le serveur qui a fourni la reponse a-t-il autorite sur le domaine? 
	 * 		TC (1 bit) : indique si le message est tronque.
	 *		RD (1 bit) : demande d'une requete recursive. 
	 * 		RA (1 bit) : indique que le serveur peut faire une demande recursive. 
	 *		UNUSED, AD, CD (1 bit chacun) : non utilises. 
	 * 		RCODE (4 bits) : code de retour.
	 *                       0 : OK, 1 : erreur sur le format de la requete,
	 *                       2: probleme du serveur, 3 : nom de domaine non trouve (valide seulement si AA), 
	 *                       4 : requete non supportee, 5 : le serveur refuse de repondre (raisons de sï¿½ecurite ou autres).
	 * QDCount : nombre de questions. 
	 * ANCount, NSCount, ARCount : nombre dï¿½entrees dans les champs ï¿½Reponseï¿½, Autorite,  Additionnel.
	 */

	protected final static int BUF_SIZE = 1024;
	protected String SERVER_DNS = null;//serveur de redirection (ip)
	protected int portRedirect = 53; // port  de redirection (par defaut)
	protected int port; // port de reception
	private String adrIP = null; //bind ip d'ecoute
	private String DomainName = "none";
	private String DNSFile = null;
	private boolean RedirectionSeulement = false;
	
	private class ClientInfo { //quick container
		public String client_ip = null;
		public int client_port = 0;
	};
	private HashMap<Integer, ClientInfo> Clients = new HashMap<>();
	
	private boolean stop = false;

	
	public UDPReceiver() {
	}

	public UDPReceiver(String SERVER_DNS, int Port) {
		this.SERVER_DNS = SERVER_DNS;
		this.port = Port;
	}
	
	public void setport(int p) {
		this.port = p;
	}

	public void setRedirectionSeulement(boolean b) {
		this.RedirectionSeulement = b;
	}

	public String gethostNameFromPacket() {
		return DomainName;
	}

	public String getAdrIP() {
		return adrIP;
	}

	private void setAdrIP(String ip) {
		adrIP = ip;
	}

	public String getSERVER_DNS() {
		return SERVER_DNS;
	}

	public void setSERVER_DNS(String server_dns) {
		this.SERVER_DNS = server_dns;
	}
	
	public void setDNSFile(String filename) {
		DNSFile = filename;
	}

	public void run() {
		try {
			DatagramSocket serveur = new DatagramSocket(this.port); // *Creation d'un socket UDP
		
			int qr = 0;
			String paquetRecuString = "";
			
			String qName = "";
			int finDeQname = 0;
			
			int identifiant = 0;
			
			UDPSender redirection;
			
			String adresseIPDuFichierDNS = null;			

			QueryFinder finder = new QueryFinder(DNSFile);
			
			UDPSender envoieReponse;
			
			int reponseType = 0;
			int reponseClasse = 0;
			
			int reponseIP = 0;
			
			String anCount = "";
			
			ArrayList<String> listeAdresse = new ArrayList();
			
			AnswerRecorder enregistrement = new AnswerRecorder(DNSFile);
			
			Scanner scanner;
			
			ArrayList<String> listeDNS = new ArrayList();
			
			// *Boucle infinie de reception
			while (!this.stop) {
				
				// Lire le datagramme requête à partir de serverSocket
				byte[] buff = new byte[0xFF];
				DatagramPacket paquetRecu = new DatagramPacket(buff,buff.length);
				System.out.println("Serveur DNS: "+serveur.getLocalAddress()+"  en attente sur le port: "+ serveur.getLocalPort());

				// *Reception d'un paquet UDP via le socket
				serveur.receive(paquetRecu);
				
				InetAddress clientIP = paquetRecu.getAddress();
				int clientPort = paquetRecu.getPort();
				
				System.out.println("paquet recu du : "+clientIP+"  du port: "+ clientPort);
				
				// *Creation d'un DataInputStream ou ByteArrayInputStream pour
				// manipuler les bytes du paquet

				ByteArrayInputStream tabInputStream = new ByteArrayInputStream (paquetRecu.getData() );
				System.out.println(buff.toString() );
				
				// Pour trouver le QR.
				// https://docs.oracle.com/javase/7/docs/api/java/util/Formatter.html#syntax
				for (byte octet : paquetRecu.getData()) 
				{
					// Remplace les espaces par des 0 car il prend certain 0 pour des espaces
					String ligneBinaire = String.format("%8s", Integer.toBinaryString(octet & 0xFF) ).replaceAll(" ", "0");
					paquetRecuString += ligneBinaire;
				}
				
				System.out.println("String de bits du paquet recu : " + paquetRecuString);
				
				//https://docs.oracle.com/javase/7/docs/api/java/lang/Integer.html#parseInt(java.lang.String,%20int)
				qr = Integer.parseInt(paquetRecuString.substring(16, 17), 2);
				
				// ****** Dans le cas d'un paquet requete *****
				if(qr == 0)
				{
					// *Lecture du Query Domain name, a partir du 13 bytes
					// On trouve aussi la fin de QNAME
					// pour trouver les adresses IP plus tard
					for(int i = 13; i <= buff.length; i++)
					{
						if(buff[i] != 0)
						{
//							System.out.println((int)Character.toChars( buff[i] )[0]);

							// *Sauvegarde du Query Domain name
							if( (int)Character.toChars( buff[i] )[0] > 20)
							{
								qName += Character.toChars( buff[i] )[0];
							}
							else
							{
								qName += ".";
								finDeQname++;
							}						
						}
						else
						{
							finDeQname += i;
							break;
						}
					}
					System.out.println("QNAME : " + qName);
					System.out.println("La fin de QNAME : " + finDeQname);
					
					// *Sauvegarde de l'adresse, du port et de l'identifiant de la requete
					// http://download.java.net/jdk7/archive/b123/docs/api/java/net/InetAddress.html
					this.setAdrIP(clientIP.toString() );
					this.setport(clientPort);
					
					System.out.println("L'adresse IP : " + getAdrIP() );
					System.out.println("Le port : " + this.port);
					
					identifiant = Integer.parseInt(paquetRecuString.substring(0, 16), 2);
					
					System.out.println("L'identifiant est : " + identifiant);

					// *Si le mode est redirection seulement
					if(RedirectionSeulement)
					{
						// *Rediriger le paquet vers le serveur DNS
						redirection = new UDPSender(SERVER_DNS, portRedirect, serveur);
						redirection.SendPacketNow(paquetRecu);						
					}
					else   // *Sinon
					{
						// *Rechercher l'adresse IP associe au Query Domain name					
						// dans le fichier de correspondance de ce serveur
//						try
//						{
						if(finder.StartResearch(qName).size() != 0)
						{
							adresseIPDuFichierDNS = finder.StartResearch(qName).get(0);
							System.out.println("Ajout de l'adresse IP : " + adresseIPDuFichierDNS);
						}
						else
						{
							System.out.println("Le fichier est vide!");
						}
							
							// *Si la correspondance n'est pas trouvee
							if( adresseIPDuFichierDNS == null )
							{
								// *Rediriger le paquet vers le serveur DNS
								redirection = new UDPSender(SERVER_DNS, portRedirect, serveur);
								redirection.SendPacketNow(paquetRecu);
							}
							else	// *Sinon
							{
								// *Creer le paquet de reponse a l'aide du UDPAnswerPaquetCreator
								UDPAnswerPacketCreator reponseInstance = UDPAnswerPacketCreator.getInstance();
								byte[] reponseByte = reponseInstance.CreateAnswerPacket(paquetRecu.getData(), finder.StartResearch(qName));
								
								// *Placer ce paquet dans le socket
								DatagramPacket paquetDeReponse = new DatagramPacket(reponseByte, reponseByte.length);
								
								// *Envoyer le paquet
								envoieReponse = new UDPSender(getAdrIP(), this.port, serveur);
								envoieReponse.SendPacketNow(paquetDeReponse);
							}
//						}
//						catch(IndexOutOfBoundsException e)
//						{
//							System.out.println("Le fichier est vide!");
//						}						
					}
				}
				else if (qr == 1)	// ****** Dans le cas d'un paquet reponse *****
				{
					// *Lecture du Query Domain name, a partir du 13ieme octet
					for(int i = 13; i <= buff.length; i++)
					{
						if(buff[i] != 0)
						{
//							System.out.println((int)Character.toChars( buff[i] )[0]);

							if( (int)Character.toChars( buff[i] )[0] > 20)
							{
								qName += Character.toChars( buff[i] )[0];
							}
							else
							{
								qName += ".";
								finDeQname++;
							}						
						}
						else
						{
							finDeQname += i;
							break;
						}
					}
					
					System.out.println("QNAME : " + qName);
					System.out.println("Fin de QUNAME : " + finDeQname);
					
					// *Passe par dessus Type et Class
					// TODO si on en a de besoin
//					int bitReponseType = (finDeQname * 8) + (6 * 8);
//					reponseType = Integer.parseInt(paquetRecuString.substring(bitReponseType, bitReponseType + 16), 2);
//					System.out.println("Type de la réponse : " + reponseType);
//					
//					int bitReponseClasse = (finDeQname * 8) + (8 * 8);
//					reponseClasse = Integer.parseInt(paquetRecuString.substring(bitReponseClasse, bitReponseClasse + 16), 2);
//					System.out.println("Classe de la réponse : " + reponseClasse);
					
					// *Passe par dessus les premiers champs du ressource record
					// pour arriver au ressource data qui contient l'adresse IP associe
					//  au hostname (dans le fond saut de 16 bytes)
					int bitReponseIP = finDeQname + (16 * 8);
					
					// *Capture de ou des adresse(s) IP (ANCOUNT est le nombre
					// de reponses retournees)
					anCount = paquetRecuString.substring(48, 64);
					System.out.println("ANCOUNT de la réponse : "+ Integer.parseInt(anCount, 2));
					
					
					
					for(int i = 0 ; i < Integer.parseInt(anCount, 2); i++)
					{
						String adresseIP = "";
						
						// (16 * 8) = position en bits du début de l'adresse IP
						// (4 * 8) = position en bit de la fin de l'adresse IP
						// (i * 8 * 4) = c'est pour indiquer qu'on saute à la prochaine adresse IP dès que le ANCOUNT augmente
						for(int j = finDeQname + 16 + (i * 4); j < finDeQname + 16 + 4 + (i * 4); j++)							
						{
							System.out.println("J : " + j);
							
//							System.out.println( (int)Character.toChars( buff[j] )[0] );

							adresseIP += Byte.toString(buff[j]);
							adresseIP += ".";
							
							System.out.println("Adresse IP : " + adresseIP);
							
							listeAdresse.add(adresseIP);
							System.out.println(listeAdresse.get(i));
						}
					}

					// *Ajouter la ou les correspondance(s) dans le fichier DNS
					// si elles ne y sont pas deja
					scanner = new Scanner(new FileReader(DNSFile));
					
					for (int i = 0; i < Integer.parseInt(anCount); i++) 
					{
						while (scanner.hasNextLine()) 
						{
							if( scanner.nextLine().contains( listeAdresse.get(i).toString() ) )
							{
								System.out.println("L'adresse IP existe deja et ne sera pas ajoute a nouveau.");
							}
							else
							{
								enregistrement.StartRecord(qName, listeAdresse.get(i).toString());
								System.out.println("L'adresse IP " + listeAdresse.get(i).toString() + " a ete ajoute.");
							}
						}
					}
					
					// *Faire parvenir le paquet reponse au demandeur original,
					// ayant emis une requete avec cet identifiant					
					UDPAnswerPacketCreator reponseInstance = UDPAnswerPacketCreator.getInstance();
					byte[] reponseByte = reponseInstance.CreateAnswerPacket(paquetRecu.getData(), finder.StartResearch(qName));
					
					// *Placer ce paquet dans le socket
					DatagramPacket paquetDeReponse = new DatagramPacket(reponseByte, reponseByte.length);
					
					// *Envoyer le paquet
					envoieReponse = new UDPSender(getAdrIP(), this.port, serveur);
					envoieReponse.SendPacketNow(paquetDeReponse);
				}
				
				qName = "";
				finDeQname = 0;
				paquetRecuString = "";
			}
//			serveur.close(); //closing server
		} catch (Exception e) {
			System.err.println("Probleme de l'execution :");
			e.printStackTrace(System.err);
		}
	}
}
