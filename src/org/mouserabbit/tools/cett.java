 /*--------------------------------------------------------------------------------------------------
     cett.java
     
     Crypto Engine Test Toool ;-)

     Nov 23 2005    Initial     
     Nov 28 2005    WIP on file encryption
     Nov 29 2005    Encrypt now. Add some basic key management in a file
     Nov 30 2005    Debug encryption. Problems with key serialisation.
     Dec 01 2005    Small changes
     Feb 23 2006    Correct the enum variable name (JDK 1.5).
     Dec 11 2006    WIP on file encryption - decryption
     Dec 12 2006    WIP on file encryption - decryption
     Dec 13 2006    WIP on file encryption - decryption. Studying padding
     Dec 16 2006    Found my error. Mixing providers!
                    Right now just using the 128 bit AES implementation from Sun
     Mar 21 2008    Bring back to mouserabbit perimeter
     Dec 29 2021    cett revival in vscode ;-)
                    Improved log4j.xml search
---------------------------------------------------------------------------------------------------*/ 


/*
 * 
 * Configuring the Provider
 * The next step is to add the provider to your list of approved providers. 
 * This step can be done statically by editing the java.security file in the lib/security directory of the SDK; 
 * therefore, if the SDK is installed in a directory called j2sdk1.2, the file would be j2sdk1.2/lib/security/java.security. 
 * One of the types of properties you can set in java.security has the following form: 
 * 
 *      security.provider.n=masterClassName
 *      
 * This declares a provider, and specifies its preference order n. 
 * The preference order is the order in which providers are searched for requested algorithms (when no specific provider is requested). 
 * The order is 1-based: 1 is the most preferred, followed by 2, and so on. 
 */


package org.mouserabbit.tools;

import java.security.Key;
import java.security.Provider;
import java.security.Security;

import java.util.Enumeration;
import java.util.StringTokenizer;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.CipherInputStream;

import java.io.File;

import javax.crypto.SecretKey;

import org.mouserabbit.utilities.log.Timer;


// import com.phaos.jce.provider.Phaos;

import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;


 public class cett {

      private static final String Version = "cett 2.28 Dec 30 2021";
      private static final int BUFFSIZE = 2 * 1024;

      // Miscellaneous
      boolean            helpmode = false;
      boolean            provlist = false;
      boolean            silent = false;
      String              log4jpath = null;
      // File parameters
      String              inputfilename = null;
      String              outputfilename = null;
      String              keyfilename = null;
      // Encryption parameters
      int                 encryptionmode = 0;
      int                 encryptkeylength = 128;
      int                 encryptkeybytes = encryptkeylength / 8;
      byte [] seed = new byte[] { (byte) 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05,
                                           0x06, 0x07, 0x08, 0x09, 0x0A,
                                           0x0B, 0x0C, 0x0D, 0x0E, 0x0F,};
      // Apache Loger
      private Logger     log = Logger.getLogger(cett.class.getName());

      public static void main (String args [])  { 
               cett bl = new cett(args); 
               System.out.println("cett starting" + bl.getClass().getName());
     }
      public cett(String args [])
      {
           Provider            provider = null;
           Provider []         providerlist = null;
           final String       providername = "SunJCE"; // Phaos discarded

           Key                 key = null;
           IvParameterSpec     iv = null;

           log.info("cett " + Version);
           try
           {
                // log4jpath = getMyLogger();
                // Analyze command line  
                ProcessCommandLine(args);
                log.info(Version);
                //
                // Optionnaly dump providers
                //
                if(provlist)  {
                     providerlist = Security.getProviders();
                     for ( int i = 0; i <  providerlist.length; ++i) {
                          provider = providerlist[i];
                          log.debug("Provider name is :" + provider.getName() + " ** " + provider.getInfo());
                          /*
                           * Dump some detailed provider information
                           * 
                           * This provider list comes from $JAVA_HOME/jre/lib/security/java.security
                           * 
                           * security.provider.1=com.sun.crypto.provider.SunJCE
                           * security.provider.2=au.net.aba.crypto.provider.ABAProvider
                           * security.provider.3=cryptix.jce.provider.CryptixCrypto
                           * security.provider.4=�
                           */
                          Enumeration en = provider.propertyNames();
                          String propertyname = null;
                          while(en.hasMoreElements()) {
                               propertyname = (String)en.nextElement();
                               log.debug("       property: " + provider.getProperty(propertyname));
                          }
                     }
                }
                /*
                int pos = Security.addProvider(new Phaos());
                if(pos == -1) { log.debug("Phaos Provider is registered in the Security provider list.");}
                else { log.debug("Provider inserted in the list with number: " + pos); }
                */
                //
                // get my prefered provider ;-)
                //
                Provider myprovider= Security.getProvider(providername);
                if(myprovider== null) throw new Exception(providername + " provider not found. I'd like to work with it.");
                log.debug("Using " + myprovider.getName() + " [" + myprovider.getInfo()  + "]" + " provider");
                //
                //   Manage the key file
                //
                byte [] buff = new byte[encryptkeybytes];
                try  {
                     /*
                      * If Key file exist, just read in the previously generated key
                      */
                     log.info("Reading key from " + keyfilename);
                     FileInputStream fis = new FileInputStream(keyfilename);
                     fis.read(buff, 0, encryptkeybytes);          // Read the Key
                     key = new SecretKeySpec(buff, "AES");
                     fis.read(buff, 0, seed.length);          // Read the IV
                     iv = new IvParameterSpec(buff);
                     fis.close();
                     log.debug("The algorithm associated to the key is : " + key.getAlgorithm());
                }
                catch(Exception e) {
                     /*
                      * Key file does not exist yet. We create it
                      * If in decipher mode, signal an error
                      */
                     if(encryptionmode == Cipher.DECRYPT_MODE)
                          throw new Exception("Cannot find the key file used for decryption");
                     log.info("Get a key generator");
                     KeyGenerator kg = KeyGenerator.getInstance("AES");
                     kg.init(encryptkeylength);
                     log.info("Generate a random key, length: " + encryptkeylength);
                     key = kg.generateKey();
                     buff = key.getEncoded();
                     iv = new IvParameterSpec(seed); 
                     byte [] initVector = iv.getIV();
                     FileOutputStream fos = new FileOutputStream(keyfilename);
                     fos.write(buff, 0, buff.length);             // Write the key and its init vector in the file
                     fos.write(initVector, 0, initVector.length);
                     fos.close();
                     log.info("Writing key in " + keyfilename);
                }
                /*
                 * Some preliminary test. Should be removed from final version
                 */
                 testCipher();
                /*
                 *    C I P H E R
                 */
                log.debug("Choose Cipher mode");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", myprovider);
                log.debug("Initialize Cipher with encoded secret key");
                cipher.init(encryptionmode, key, iv);
                log.debug("Process input file " + inputfilename);
                FileInputStream fis = new FileInputStream(inputfilename);
                FileOutputStream fos = new FileOutputStream(outputfilename);

                /*
                 * Now loops to encrypt/ decrypt the file
                 */               
                byte[]         buffer = new byte[BUFFSIZE];
                int bytesread = 0;
                int rounds = 0;
                Timer tt = new Timer();
                /*
                 * Two # loops, depending on the mode
                 */
                if(encryptionmode == Cipher.ENCRYPT_MODE) {
                     CipherOutputStream cos = new CipherOutputStream(fos, cipher);                    
                     try {
                          while((bytesread = fis.read(buffer, 0, BUFFSIZE)) >= 0) {
                               Timer itt = new Timer();
                               cos.write(buffer, 0, bytesread);
                               ++rounds;
                               if(!silent)
                                    log.debug("         ** Writing " + bytesread + " to output file (" + rounds + ") : " + 
                                         itt.getTimerString());
                          }
                          log.info("Encoded the file in " + tt.getTimerString());
                     }
                     catch (Exception ex) {
                          log.debug("Exception catched during the encipher process...");
                     }
                     finally {
                          fis.close();
                          cos.close();
                     }
                     log.info("Encoded the file in " + tt.getTimerString());
                }
                else {
                     CipherInputStream cis = new CipherInputStream(fis, cipher);    
                     try {
                          while((bytesread = cis.read(buffer, 0, BUFFSIZE)) >= 0) {
                               Timer itt = new Timer();
                               fos.write(buffer, 0, bytesread);
                               ++rounds;
                               if(!silent)
                                    log.debug("         ** Writing " + bytesread + " to output file (" + rounds + ") : " + 
                                         itt.getTimerString());
                          }
                     }
                     catch (Exception ex) {
                          log.debug("Exception catched during the decipher process...");
                     }
                     finally {
                          fos.close();
                          cis.close();
                     }
                     log.info("Decoded the file in " + tt.getTimerString());
                }
                // Shoot provider (unnecessary, just to test the API
                Security.removeProvider("Phaos");
           }
           catch( Exception ex )
           {
                if(helpmode)
                     Usage();
                else
                     if(log4jpath == null)
                          System.out.println("Error ** : " + ex.getMessage());
                     else
                          log.error("Error ** : " + ex.getMessage());
                System.exit(1);
           }
           finally {           
           }
           System.out.print("\n\n");
           System.exit(0);
      }
      /*-----------------------------------------------------------------------------------------
       * Just used to test some cipher capabilities and understand how it works
      -------------------------------------------------------------------------------------------*/
      private void testCipher() {

          try {
               Cipher cipher = Cipher.getInstance("AES");
               // Get the KeyGenerator
               KeyGenerator kgen = KeyGenerator.getInstance("AES");
               kgen.init(128); // 192 and 256 bits may not be available

               // Generate the secret key specs.
               SecretKey skey = kgen.generateKey();
               byte[] raw = skey.getEncoded();

               SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
               /*
                * Dummy code for my understanding of ciphers
                */
               log.debug("Algorithm used: " + cipher.getAlgorithm());
               log.debug("Provider is   : " + cipher.getProvider());
               log.debug("Block size is : " + cipher.getBlockSize());
               String password = "012345678901234567890123456789";
               /*
                * Encrypt
                */
               cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
               byte [] plainpassword = password.getBytes();
               byte [] cipherpassword = cipher.doFinal(plainpassword);
               log.debug("Encrypted password: " + asHex(cipherpassword));
               /*
                * Decrypt
                */
               cipher.init(Cipher.DECRYPT_MODE, skeySpec);
               byte[] original = cipher.doFinal(cipherpassword);
               String originalString = new String(original);
               log.debug("Decrypted password: " + originalString + " " + asHex(original));
               
          }
          catch(Exception e) {
               log.error("An exception occured in testCipher: " + e.getMessage());
          }
      }
      /*-----------------------------------------------------------------------------------------
       * Convert an encrypted buffer into a readable string
      -------------------------------------------------------------------------------------------*/
      private String asHex(byte[] buf) {
           StringBuffer strbuf = new StringBuffer(buf.length * 2);
           int i;

           for (i = 0; i < buf.length; i++) {
                if (((int)buf[i] & 0xff) < 0x10)
                     strbuf.append("0");

                strbuf.append(Long.toString((int)buf[i] & 0xff, 16));
           }

           return strbuf.toString();
      }
      /*-----------------------------------------------------------------------------------------
           Some code to get an Apache logger
           Scans the class path and searches for a file named:
           <classname>log4j.xml
      -------------------------------------------------------------------------------------------*/
      private String getMyLogger() throws Exception
      {
           //
           //   Searching for my log4j.xml file
           //   Basic search, scanning directories in classpath and locating
           //   a log4j.xml file
           //
           StringTokenizer tokenizer = 
                new StringTokenizer(System.getProperty("java.class.path"), 
                                         File.pathSeparator, false);
           String dap = null;
           String fullyqualifiedlog4jpath = null;
           
           while ( tokenizer.hasMoreTokens() ) {
                String classpathElement = tokenizer.nextToken();
                File classpathFile = new File(classpathElement);
                if ( classpathFile.isDirectory() ) {
                     dap = classpathFile.getAbsolutePath();
                     File fap = new File(dap + File.separator + "log4j.xml");
                     if(fap.exists()) 
                     {
                          fullyqualifiedlog4jpath = fap.getAbsolutePath();
                          break;
                     }
                }
           }
           if(fullyqualifiedlog4jpath == null) {  // No log4j.xml located in classpath
                                                  // try alternate command line method :  -Dlog4j.config=log4j.xml
               System.out.print("\n\n\n");
               String logfile = System.getProperty("log4j.config");
               if ( logfile == null ){
                  System.out.print("You must set log4j.config environment variable on the command line\n");
                  System.out.print("java -Dlog4j.config=\"YOURLOCATION\\log4j.xml\" -jar BaseConnect.jar\n");
                  throw new Exception("log4j.config command line parameter not passed.");
               }
               DOMConfigurator.configure(System.getProperty("log4j.config"));
               log = Logger.getLogger(cett.class.getName());
               log.info(Version + " Starting");

           } 
           return fullyqualifiedlog4jpath;
      }
      /*-----------------------------------------------------------------------------------------
           Analyze command line arguments
           YT : DEC 30 2021 Add log4j quakifier
      -------------------------------------------------------------------------------------------*/
      void ProcessCommandLine(String[] args) throws Exception
      {
           boolean recognized = false;

           for(int loop = 0; loop < args.length; ++loop)
           {
                recognized = false;
                if(args[loop].equals("-log4j")) {
                    recognized = true;
                    log4jpath = args[++loop].toString();
               }
               if(args[loop].equals("-p")) {
                    recognized = true;
                    provlist = true;
               }
              if(args[loop].equals("-s")) {
                     recognized = true;
                     silent = true;
                }
                if(args[loop].equals("-e")) {
                     recognized = true;
                     encryptionmode = Cipher.ENCRYPT_MODE;
                }
                if(args[loop].equals("-d")) {
                     recognized = true;
                     encryptionmode = Cipher.DECRYPT_MODE;
                }
                if(args[loop].equals("-k")) {
                     recognized = true;
                     keyfilename = args[++loop].toString();
                }
                if(args[loop].equals("-h")) {
                     recognized = true;
                     helpmode = true;
                     throw new Exception("Help requested");
                }
                if(args[loop].equals("-help")) {
                     recognized = true;
                     helpmode = true;
                     throw new Exception("Help requested");
                }
                if(args[loop].equals("?")) {
                     recognized = true;
                     helpmode = true;
                     throw new Exception("Help requested");
                }
                if(args[loop].equals("-i")) {
                     if(loop < args.length) inputfilename = args[++loop].toString();
                     recognized = true;
                }
                if(args[loop].equals("-o")) {
                     if(loop < args.length) outputfilename = args[++loop].toString();
                     recognized = true;
                }
                if(!recognized) {
                     if(args[loop].startsWith("-"))
                     {
                          throw new Exception("Unrecognized qualifier : " + args[loop].toString());
                     }
                }
           }
           //
           //   Some controls.
           //
           if (log4jpath == null) {
                throw new Exception("Please specify the log4j.xml file location with -log4j qualifier");
           }
           else {
               DOMConfigurator.configure(log4jpath);
           }
           if(encryptionmode == 0)
                throw new Exception("Encrypt or decrypt?");
           if(keyfilename == null)
                throw new Exception("Give a name for  key file (existing or not)");
           if(inputfilename == null)
                throw new Exception("Give one input file to process");
           if(outputfilename == null)
                throw new Exception("Give one output file to process");
           if(outputfilename.equals(inputfilename))
                throw new Exception("Output file name must be DIFFERENT from input!");
      }
      /*-----------------------------------------------------------------------------------------
           Usage
      -------------------------------------------------------------------------------------------*/
      static void Usage()
      {
           System.err.print("\nUsage:");
           System.err.print("\n\ncett -log4j log4j.xml -e|d -k filespec -i filespec -o filespec [-p] [-h|?|help] [-s (silent)]");
           System.err.print("\n");
      }
 }