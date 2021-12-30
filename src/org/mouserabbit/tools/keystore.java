/*--------------------------------------------------------------------------------------------------
     keystore.java

     May 08 2007    Initial
---------------------------------------------------------------------------------------------------*/
package org.mouserabbit.sqljava;

import java.io.File;

import java.io.FileInputStream;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import java.security.cert.X509Certificate;

import java.util.Enumeration;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;


public class keystore {

     //TODO: Version update
     
     private static String Version = "keystore V 1.17 May 07 2007, ";
     private static String keyfile = null;
     private static String password = null;

     static Logger log = null;

     //-------------------------------------------------------------------------------
     // S T A R T   H E R E 
     //-------------------------------------------------------------------------------
     public static void main (String args []) {

          FileInputStream in = null;

          try
          {
               System.out.print("\n\n\n");
               getLog4jPath();     // Initialize log4j
               log = Logger.getLogger(keystore.class.getName());
               log.info(Version + "Starting");
               //-----------------------
               // Analyze command line
               //-----------------------
               ProcessCommandLine(args);
               /*
                * Now go on...
                */
               KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
               // Load the keystore contents
               in = new FileInputStream(keyfile);
               ks.load(in, password.toCharArray());
               /*
                * Dump some aliases
                */
               Enumeration en = ks.aliases();
               String alias = null;
               while(en.hasMoreElements()){
                    alias = (String)en.nextElement();
                    log.info(Version + "Alias: " + alias);
                    Certificate ct = ks.getCertificate(alias);
                    if(ct != null){
                         log.info(Version + "\tAlias type * " + ct.getType());
                         if(ct.getType().equals("X.509")){
                              X509Certificate x = (X509Certificate)ct;
                              log.info(Version + "\t\tIssuer    :" + x.getIssuerDN().getName());
                              log.info(Version + "\t\tSubject   :" + x.getSubjectDN().getName());
                              log.info(Version + "\t\tNot before:" + x.getNotBefore().toGMTString());
                              log.info(Version + "\t\tNot after :" + x.getNotAfter().toGMTString());
                              PublicKey pbk = x.getPublicKey();
                              log.info(Version + "\t\tPublic key:" + pbk.toString());
                         }
                    }
                    /*
                     * Get private key
                     */
                    Key key = ks.getKey(alias, password.toCharArray());
                    if (key instanceof PrivateKey) {
                         log.info(Version + "\t\tPrivate key:" + key.toString()); 
                         // Get public key
                         PublicKey publicKey = ct.getPublicKey();
                         log.info(Version + "\t\tPublic key:" + publicKey.toString()); 
                         // Builds a key pair
                         KeyPair kp = new KeyPair(publicKey, (PrivateKey)key);
                    }
               }
          }
          catch( Exception ex )
          {
               log.error(Version + ex.getMessage());
               Usage();
               System.exit(1);
          }
          finally {
               try {in.close(); } catch ( Exception exfin){ ; }
          }
          log.info(Version + "End of job");
          System.out.print("\n\n");
          System.exit(0);
     }
     /*-----------------------------------------------------------------------------------------
          Analyze command line arguments
     -------------------------------------------------------------------------------------------*/
     static protected void ProcessCommandLine(String[] args) throws Exception
     {
          boolean recognized = false;

          for(int loop = 0; loop < args.length; ++loop)
          {
               recognized = false;
               if(args[loop].equals(new String("-ks")))
               {
                    if(loop < args.length) keyfile = args[++loop].toString();
                    recognized = true;
               }
               if(args[loop].equals(new String("-p")))
               {
                    if(loop < args.length) password = args[++loop].toString();
                    recognized = true;
               }
               if(!recognized)
               {
                    if(args[loop].startsWith("-"))
                    {
                         throw new Exception("Unrecognized qualifier : " + args[loop].toString());
                    }
               }
          }
          //
          //   Some controls. Probably not exhaustive!
          //
          if(keyfile == null)throw new Exception("You must specify a keystore file location [-ks].");
          if(password == null)throw new Exception("You must specify a keystore file password [-p].");
     }
     
     /*-----------------------------------------------------------------------------------------
      * Searching for my log4j.xml file 
      * Basic search, scanning directories in classpath and locating
      * a log4j.xml file
     -------------------------------------------------------------------------------------------*/
     static void getLog4jPath() throws Exception {
          StringTokenizer tokenizer = new StringTokenizer(System.getProperty("java.class.path"), 
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
          if(fullyqualifiedlog4jpath == null) throw new Exception("Unable to locate a log4j.xml file in your path.");
          DOMConfigurator.configure(fullyqualifiedlog4jpath);
     }     
     /*-----------------------------------------------------------------------------------------
          Usage
     -------------------------------------------------------------------------------------------*/
     static void Usage()
     {
          System.err.print("\nUsage:");
          System.err.print("\n\nkeystore -ks keystorefile -p keystorefilepassword");
          System.err.print("\n");
     }
}

