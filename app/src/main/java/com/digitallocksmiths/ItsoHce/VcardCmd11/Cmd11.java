package com.digitallocksmiths.ItsoHce.VcardCmd11;

// ToDo: Consider this strategy....
//       Select: Copy NVM sectors to RAM.
//       Process: Work directly on RAM copies.
//       EndSession: If verified, copy RAM to NVM.
//       Combine sectors and MMMT is a mega structure.
//       Keep version A/B encrypted with Keys A/B
//       Key changes on every save.
//


import android.util.Log;

import com.digitallocksmiths.ItsoHce.Itso.Directory;
import com.digitallocksmiths.ItsoHce.VCard;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Cmd11 extends VCard {
    private static final String TAG = "Cmd11";

    private static final byte  bCHAL_SIZE       =   8;                                              // Size of Random Challenge Data

    private static final short sPAGE_SIZE         = 256;                                            // size of sector (IPE or VRG records)
    private static class Sector   { byte[] baBody = new byte[sPAGE_SIZE]; }

    private static final byte  bPWD_SIZE        =   8;                                              // Size of Password Data
    private static class Password { byte[] baBody = new byte[bPWD_SIZE];  }

    // ToDo: ITSO ref is 228. Who's right?
    public static final short sMAXIPE_SIZE 		= (255 - 8 - 16);                                   // pwd[8] :: Ipe[x] :: Seal[16]  =< 255 bytes.
    public static final byte  bCSS_SIZE     	=  8;                                               // Size of Commital Confirmation Signature.

    // ==========================================================================
    // Clear on reset 'RAM' variables

    public byte[]  baChallenge          = new byte[bCHAL_SIZE];
    public byte[]  baChallengeTemp      = new byte[bCHAL_SIZE];

    // ToDo: Make these booleans a secure boolean variant.
    public boolean fAuthenticated       = false;                                                    // Bool vars
    public boolean fPseudoAuthenticated = false;
    public boolean fUsingPseudoShellUID = false;
    //public short   sFciStart            = 0;                                                        // Short vars
    //public short   sFciA5LenOffset      = 0;
    //public short   sAllocated           = 0;

    // ==========================================================================
    // NV variables

    private byte[] baAid;
    private byte[] mAuthDesKeyA;
    private byte[] mAuthDesKeyB;
    private byte[] mAuthPseudoKeyA;
    private byte[] mAuthPseudoKeyB;
    //private byte[] baShell;
    private byte[] baPseudoShell;
    private byte[] baUID;
    private byte[] baPseudoUID;
    private byte[] baCapabillities;
    private byte[] baAuthKasParams;

    private byte[]       baCSS       = new byte[bCSS_SIZE];                                         // Commit Confirmation Signature
    private int          iTsn;                                                                      // Transaction Sequence Number;

    // not needed? private Sector   Shell;                                                          //     0: Shell
    private Sector[]     aIpe;                                                                      // 1-E-1: Ipes      (0..E-2)
    private Sector[]     aVrg;                                                                      // 1-E-1: Vrgs      (1..E-2)
    private Sector       TTLog;                                                                     //     E: Log       (E-1)
    private Directory    directory;                                                                 //   E+1: Directory (E)
    private Password[]   aPassword;                                                                 // 1-E+1: Password  (0-E)


    private       SecretKey       DesKeyA;                                                          // initialized on image load.
    private       SecretKey       DesKeyB;                                                          //
    private       SecretKey       DesKeyPseudoA;                                                    //
    private       SecretKey       DesKeyPseudoB;                                                    //

    private       SecretKey       SessionKey;                                                       // ephemeral session key.
    private final SecureRandom    Rng;                                                              // Random generator.
    public  final Cipher          Cip;                                                              // challenge processor/SK generator.
    private final MessageDigest   Hash;                                                             // session MAC generator
    private final IvParameterSpec NullIV = new IvParameterSpec(new byte[8]);                        // IV = 0.0.0.0.0.0.0.0



//  public static Checksum      Crc;                                                                //        CRC resource.
    public final  Cipher        Sig;                                                                // 		  MAC verifyer/generator. (DES needs to use a Cipher and grab the result)
//  public static DESKey        SessionKey;                                                         //        ephemeral (transient) session key.
//  public static MessageDigest Hash;                                                               //		  Apdu Message digest.


    // ========================================
    // Constructor
    //
    // ========================================
    public Cmd11()  throws VCard.VirtualCardException {
        super();
        NameSet("CMD 11");

        int iE = shell.getE();

        aIpe = new Sector[iE-1];                                                                    // Allocate sectors according to the shell's E
        aVrg = new Sector[iE-1];                                                                    // ditto for VRGs
        for (int i=0; i< iE-1; i++) {                                                               // they are all sector sized
            aIpe[i] = new Sector();
            aVrg[i] = new Sector();
        }
        TTLog = new Sector();                                                                       // TT Log is also sector sized.
        aPassword       = new Password[iE+1];                                                       // Passwords are 1 per sector + 1 for TTLog & 1 for Directory
        for (int i = 0; i < aPassword.length; i++) {
            aPassword[i] = new Password();
        }
        // Deserialize will create and assign byte[]s.

        try {
            Rng  = new SecureRandom();
            Hash = MessageDigest.getInstance("SHA-256");
            Cip  = Cipher.getInstance("DESede/CBC/NoPadding");
            Sig  = Cipher.getInstance("DESede/CBC/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            Log.e(TAG, "Cmd11: Crypto trouble ", e);
            throw new VCard.VirtualCardException("Crypto Algorithm missing");
        }

            // ToDo: Do we need to allocate the space.
        // Just need to ensure JSON parser fills the correct size.
        // also safe disposal of replaced data structures.
    }                                                                                               // Exit with all space allocated, to be populated later.


    // ========================================
    // ImageGetSize()
    //    Return the size of the serialized image in bytes.
    // ========================================
    protected int   ImageGetSize() {                                                                // subclasses indicate their own storage volume requirements
        Log.d(TAG, "ImageGetSize");
        // ToDo: Sizeof the image here.
        return  SerializeOverhead + baCSS.length +
                4   /* sizeof(iTsn) */  +
                SerializeOverhead + baAid.length +
                SerializeOverhead + mAuthDesKeyA.length +
                SerializeOverhead + mAuthDesKeyB.length +
                SerializeOverhead + mAuthPseudoKeyA.length +
                SerializeOverhead + mAuthPseudoKeyB.length +
                SerializeOverhead + baPseudoShell.length +
                SerializeOverhead + baUID.length +
                SerializeOverhead + baPseudoUID.length +
                SerializeOverhead + baCapabillities.length +
                SerializeOverhead + baAuthKasParams.length +
               (SerializeOverhead + sPAGE_SIZE)  * aIpe.length +
               (SerializeOverhead + sPAGE_SIZE)  * aVrg.length +
                SerializeOverhead + sPAGE_SIZE  /* TTLog */ +
                SerializeOverhead + directory.getLength() +
               (SerializeOverhead + bPWD_SIZE)   * aPassword.length;
    };

    // ========================================
    // ImageDeserialize()
    //      Make a new VCard from NVM store.
    // ========================================
    protected void  ImageDeserialize(ByteBuffer buffer) throws VirtualCardException {                                           // subclasses populate their working variables here.
        Log.d(TAG, "ImageDeserialize");
        try {
            baCSS              = DeserializeByteArray(buffer);
            iTsn               = buffer.getInt();
            baAid              = DeserializeByteArray(buffer);
            mAuthDesKeyA       = DeserializeByteArray(buffer);
            mAuthDesKeyB       = DeserializeByteArray(buffer);
            mAuthPseudoKeyA    = DeserializeByteArray(buffer);
            mAuthPseudoKeyB    = DeserializeByteArray(buffer);
            baPseudoShell      = DeserializeByteArray(buffer);
            baUID              = DeserializeByteArray(buffer);
            baPseudoUID        = DeserializeByteArray(buffer);
            baCapabillities    = DeserializeByteArray(buffer);
            baAuthKasParams    = DeserializeByteArray(buffer);
            for (Sector sector : aIpe) {
                sector.baBody  = DeserializeByteArray(buffer);
            }
            for (Sector sector : aVrg) {
                sector.baBody  = DeserializeByteArray(buffer);
            }
            TTLog.baBody       = DeserializeByteArray(buffer);
            directory          = new Directory(shell, DeserializeByteArray(buffer));
            for (Password password : aPassword) {
               password.baBody = DeserializeByteArray(buffer);
            }

            if ((mAuthDesKeyA    != null)  && (mAuthDesKeyA.length    > 0)) { DesKeyA       = ConstructDesKey(mAuthDesKeyA); }
            if ((mAuthDesKeyB    != null)  && (mAuthDesKeyB.length    > 0)) { DesKeyB       = ConstructDesKey(mAuthDesKeyB); }
            if ((mAuthPseudoKeyA != null)  && (mAuthPseudoKeyA.length > 0)) { DesKeyPseudoA = ConstructDesKey(mAuthPseudoKeyA); }
            if ((mAuthPseudoKeyB != null)  && (mAuthPseudoKeyB.length > 0)) { DesKeyPseudoB = ConstructDesKey(mAuthPseudoKeyB); }
        }
        catch (VirtualCardException  e) {
            Log.d(TAG, "ImageDeserialize: Corrupt Image file");
            throw e;
        }
    }



    // ========================================
    // ImageSerialize()
    //      Add this class's image variables
    //      to the buffer.
    // ========================================
    protected void  ImageSerialize(ByteBuffer buffer) {                                             // subclasses serialize their variables here.
        Log.d(TAG, "ImageSerialize");
        VCard.SerializeByteArray(buffer, baCSS);
        buffer.putInt(iTsn);
        SerializeByteArray(buffer, baAid);
        SerializeByteArray(buffer, mAuthDesKeyA);
        SerializeByteArray(buffer, mAuthDesKeyB);
        SerializeByteArray(buffer, mAuthPseudoKeyA);
        SerializeByteArray(buffer, mAuthPseudoKeyB);
        SerializeByteArray(buffer, baPseudoShell);
        SerializeByteArray(buffer, baUID);
        SerializeByteArray(buffer, baPseudoUID);
        SerializeByteArray(buffer, baCapabillities);
        SerializeByteArray(buffer, baAuthKasParams);
        for (Sector sector : aIpe)            { SerializeByteArray( buffer, sector.baBody);   }
        for (Sector sector : aVrg)            { SerializeByteArray( buffer, sector.baBody);   }
        SerializeByteArray( buffer, TTLog.baBody);
        SerializeByteArray( buffer, directory.Get());
        for (Password password : aPassword)   { SerializeByteArray(buffer,  password.baBody); }
    }

    // ========================================
    // JsonParse(JSONObject szJsonCardImage)
    //      Make a new VCard from the JSON image.
    // ========================================
    protected void  JsonParse(JSONObject jsonCardImage) throws JSONException, VirtualCardException {  // parse the JSON image into the CM Image
        Log.d(TAG, "JsonParse");

        // shell was read and parsed by the caller.

        iTsn    = 0;                                                                                // new image so start the transaction counter form zero
        Arrays.fill(baCSS, (byte)0);                                                                // And clear the CSS

        baAid           = DecodeJsonByteArray(jsonCardImage, "baAid");
        mAuthDesKeyA    = DecodeJsonByteArray(jsonCardImage, "mAuthDesKeyA");
        mAuthDesKeyB    = DecodeJsonByteArray(jsonCardImage, "mAuthDesKeyB");
        mAuthPseudoKeyA = DecodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyA");
        mAuthPseudoKeyB = DecodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyB");
        baPseudoShell   = DecodeJsonByteArray(jsonCardImage, "baPseudoShell");
        baUID           = DecodeJsonByteArray(jsonCardImage, "baUID");
        baPseudoUID     = DecodeJsonByteArray(jsonCardImage, "baPseudoUID");
        baCapabillities = DecodeJsonByteArray(jsonCardImage, "baCapabillities");
        baAuthKasParams = DecodeJsonByteArray(jsonCardImage, "baAuthKasParams");

        int iSector = 1;
        JSONArray ipeList = jsonCardImage.getJSONArray("baIpeList");                          // Ipes and Vrgs into sectors
        for (int i = 0; i < ipeList.length(); i++) {                                                // should be E-1 of them.
            JSONObject ipe;
            try                     { ipe = ipeList.getJSONObject(i); }
            catch (JSONException e) { ipe = null;                     }
            if (ipe != null && ipe.length() == 2) {
                setIpe(iSector, DecodeJsonByteArray(ipe, "baIpe"));
                setVrg(iSector, DecodeJsonByteArray(ipe, "baVrg"));
            }
            iSector++;
        }

        setLog(DecodeJsonByteArray(jsonCardImage, "baLog"));                                  // Log into a sector
        directory       = new Directory(shell, DecodeJsonByteArray(jsonCardImage, "baDir"));  // Dir into a sector

        JSONArray pwdList = jsonCardImage.getJSONArray("PasswordList");                       // Passwords into sectors
        for (int i = 0; i < pwdList.length(); i++) {                                                // should be E of them.
            setPwd(i, DecodeStringToByteArray(pwdList.getString(i)));
        }
        // If we are successful the caller will erase the old image and then call SaveImage().
        //
        if ((mAuthDesKeyA    != null)  && (mAuthDesKeyA.length    > 0)) { DesKeyA       = ConstructDesKey(mAuthDesKeyA); }
        if ((mAuthDesKeyB    != null)  && (mAuthDesKeyB.length    > 0)) { DesKeyB       = ConstructDesKey(mAuthDesKeyB); }
        if ((mAuthPseudoKeyA != null)  && (mAuthPseudoKeyA.length > 0)) { DesKeyPseudoA = ConstructDesKey(mAuthPseudoKeyA); }
        if ((mAuthPseudoKeyB != null)  && (mAuthPseudoKeyB.length > 0)) { DesKeyPseudoB = ConstructDesKey(mAuthPseudoKeyB); }

    }


    // ========================================
    // JsonExport()
    //      Save the CM image to the NVM store.
    // ========================================
    protected void  JsonExport(JSONObject jsonCardImage) throws JSONException {                     // Add data to the JSON object.
        Log.d(TAG, "JsonExport");

        EncodeJsonByteArray(jsonCardImage, "baAid",           baAid);
        EncodeJsonByteArray(jsonCardImage, "mAuthDesKeyA",    mAuthDesKeyA);
        EncodeJsonByteArray(jsonCardImage, "mAuthDesKeyB",    mAuthDesKeyB);
        EncodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyA", mAuthPseudoKeyA);
        EncodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyB", mAuthPseudoKeyB);
        EncodeJsonByteArray(jsonCardImage, "baPseudoShell",   baPseudoShell);
        EncodeJsonByteArray(jsonCardImage, "baUID",          baUID );
        EncodeJsonByteArray(jsonCardImage, "baPseudoUID",     baPseudoUID);
        EncodeJsonByteArray(jsonCardImage, "baCapabillities", baCapabillities);
        EncodeJsonByteArray(jsonCardImage, "baAuthKasParams", baAuthKasParams);
        EncodeJsonByteArray(jsonCardImage, "baDir",           directory.Get());
        EncodeJsonByteArray(jsonCardImage, "baLog",           TTLog.baBody);
        JSONArray ipeList = new JSONArray();
        for (int i = 1; i < shell.getE(); i++) {
            if (directory.E_Empty(i)) {
                JSONObject ipe = new JSONObject();
                EncodeJsonByteArray(ipe, "baIpe", getIpe(i));
                EncodeJsonByteArray(ipe, "baVrg", getVrg(i));
                ipeList.put(ipe);
            }
            else {
                ipeList.put(JSONObject.NULL);
            }
        }
        jsonCardImage.put("baIpeList", ipeList);
        JSONArray pwdList = new JSONArray();
        for (Password password : aPassword) {
            pwdList.put(EncodeByteArrayToString(password.baBody));
        }
        jsonCardImage.put("PasswordList", pwdList);
    }


    // =============================================================================================    Reset (abstract implementation)
    // ========================================
    // Reset()
    //      clear/init working variables.
    //      return the FCI
    // ========================================
    public void Reset() throws VirtualCardException {                                               // Card reset
        Log.d(TAG, "Reset");
        // ToDo: Clear CM Ram vars here. Maybe read the image?

        Arrays.fill(baChallenge,     (byte)0);
        Arrays.fill(baChallengeTemp, (byte)0);
        fAuthenticated       = false;
        fPseudoAuthenticated = false;
        fUsingPseudoShellUID = (baPseudoShell != null && baPseudoShell.length > 0);                 // if we have a pseudo shell, we are "using it".
    }

    // =============================================================================================    Dispose (abstract implementation)
    // ========================================
    // Dispose()
    //      overwrite secret data before the
    //      instance is left to the GC.
    // ========================================
    public void Dispose() {                                                                         // Card disposal
        Log.d(TAG, "Dispose");

        Scrub(mAuthDesKeyA);                                                                        // Raw key material
        Scrub(mAuthDesKeyB);                                                                        //
        Scrub(mAuthPseudoKeyA);                                                                     //
        Scrub(mAuthPseudoKeyB);                                                                     //
        mAuthDesKeyA = mAuthDesKeyB = mAuthPseudoKeyA = mAuthPseudoKeyB = null;                     //

        DesKeyA       = Destroy(DesKeyA);                                                           // Key objects
        DesKeyB       = Destroy(DesKeyB);                                                           //
        DesKeyPseudoA = Destroy(DesKeyPseudoA);                                                     //
        DesKeyPseudoB = Destroy(DesKeyPseudoB);                                                     //
        SessionKey    = Destroy(SessionKey);                                                        //

        if (aPassword != null) {                                                                    // Passwords
            for (Password password : aPassword) {                                                   //
                if (password != null) { Scrub(password.baBody); }                                   //
            }                                                                                       //
        }                                                                                           //

        Scrub(baChallenge);                                                                         // Session state
        Scrub(baChallengeTemp);                                                                     //
        Scrub(baCSS);                                                                               //
        Hash.reset();                                                                               //      APDU hash holds session traffic
        fAuthenticated       = false;                                                               //
        fPseudoAuthenticated = false;                                                               //
    }

    // =============================================================================================    Select (abstract implementation)
    // ========================================
    // Select()
    //      construct and return the FCI
    // ========================================
    public byte[] Select(byte[] baAid) {                                                            // *** Card select
        Log.d(TAG, "Select");                                                                       //
        if (fUsingPseudoShellUID) { return WrapAsFci(baAid, FciBuildRandom()); }                    // Build FCI for random  UID host
        else                      { return WrapAsFci(baAid, FciBuildStatic()); }                    //               static  UID host
    }                                                                                               //


    private static final byte bTagShell          = (byte)0xC0;                                      // FCI Tags
    private static final byte bTagCapabilities   = (byte)0xC1;                                      //
    private static final byte bTagDirectory      = (byte)0xC2;                                      //
    private static final byte bTagOidList        = (byte)0xC3;                                      //
    private static final byte bTagCss            = (byte)0xC4;                                      //
    private static final byte bTagChallenge      = (byte)0xC5;                                      //
    private static final byte bTagPseudoUid      = (byte)0xC6;                                      //
    private static final byte bTagStaticUid      = (byte)0xC7;                                      //
    private static final byte bTagAuth           = (byte)0xC8;                                      //

    private byte[] FciBuildStatic() {                                                               // *** Static UID FCI
        ArrayList<byte[]> tagList = new ArrayList<>();
        tagList.add(TlvBuild(bTagShell,        baShell));
        tagList.add(TlvBuild(bTagCapabilities, baCapabillities));
        tagList.add(TlvBuild(bTagDirectory,    directory.Get()));
        tagList.add(TlvBuild(bTagOidList,      ConstructOids()));
        tagList.add(TlvBuild(bTagCss,          baCSS));
        tagList.add(TlvBuild(bTagChallenge,    ConstructChallenge(DesKeyA)));
        tagList.add(TlvBuild(bTagStaticUid,    baUID));                                             // non standard...
        tagList.add(TlvBuild(bTagAuth,         baAuthKasParams));
        return TlvBuild((byte)0xA5, tagList);
    }

    private byte[] FciBuildRandom() {                                                               // *** Random UID FCI
        ArrayList<byte[]> tagList = new ArrayList<>();
        tagList.add(TlvBuild(bTagShell,        baPseudoShell));
        tagList.add(TlvBuild(bTagCapabilities, baCapabillities));
        tagList.add(TlvBuild(bTagCss,          baCSS));
        tagList.add(TlvBuild(bTagChallenge,    ConstructChallenge(DesKeyPseudoA)));
        tagList.add(TlvBuild(bTagPseudoUid,    baPseudoUID));
        tagList.add(TlvBuild(bTagAuth,         baAuthKasParams));
        return TlvBuild((byte)0xA5, tagList);
    }

    private byte[] FciBuildReselect() {                                                             // *** Reselection FCI
        ArrayList<byte[]> tagList = new ArrayList<>();
        tagList.add(TlvBuild(bTagShell,        baShell));
        tagList.add(TlvBuild(bTagDirectory,    directory.Get()));
        tagList.add(TlvBuild(bTagOidList,      ConstructOids()));
        tagList.add(TlvBuild(bTagChallenge,    ConstructChallenge(DesKeyA)));
        tagList.add(TlvBuild(bTagStaticUid,    baUID));
        tagList.add(TlvBuild(bTagAuth,         baAuthKasParams));
        return TlvBuild((byte)0xA5, tagList);
    }



    private byte[] ConstructChallenge(SecretKey key) {                                              // *** ConstructChallenge
        Rng.nextBytes(baChallenge);                                                                 //  make random challenge
        // ToDo: Debug code here.
        //baChallenge[0] = (byte)0x61;                                                              //
        //baChallenge[1] = (byte)0x62;                                                              //
        //baChallenge[2] = (byte)0x63;                                                              //
        //baChallenge[3] = (byte)0x64;                                                              //
        //baChallenge[4] = (byte)0x65;                                                              //
        //baChallenge[5] = (byte)0x66;                                                              //
        //baChallenge[6] = (byte)0x67;                                                              //
        //baChallenge[7] = (byte)0x68;                                                              //

        if (shell.getKsc() == 0x04) {                                                               // ? DESFire style
            try {                                                                                   //
                Cip.init(Cipher.ENCRYPT_MODE, key, NullIV);                                         //      it needs to be encrypted
                baChallengeTemp = Cip.doFinal(baChallenge);                                         //
            } catch (Exception e) {                                                                 //
                Log.e(TAG, "ConstructChallenge: Encryption failed: " + e.getMessage());             //       report problems.
                System.arraycopy(baChallenge, 0, baChallengeTemp, 0, bCHAL_SIZE);                   //
            }                                                                                       //
        }                                                                                           //
        else {                                                                                      // ? CMD2 style
            System.arraycopy(baChallenge, 0, baChallengeTemp, 0, bCHAL_SIZE);                       //
        }                                                                                           //
                                                                                                    //
        return baChallengeTemp;                                                                     // That's all folks.
    }                                                                                               //

    private byte[] ConstructOids() {                                                                // *** ConstructOids
        byte[] baOids = new byte[2 * (shell.getE()-1)];                                             //      make a list of the IPE owners.
        for (int i = 1; i < shell.getE()-1; i++) {                                                  //      One enty for each E/possible IPE
            short sOid = 0;                                                                         //
            if (!directory.E_Empty(i)) {                                                            //      used?
                sOid = directory.E_Oid(i);                                                          //      get the OID (13 bits from directory.E[i])
                if (directory.E_Ext(i)) {                                                           //      Do we need to extend the OID by the ISAM fudge factor?
                    int iOff = 2 + aIpe[i-1].baBody[0] & (byte)0xFC;                                //          Top bits are collected from the IPE's instance ID
                    switch (aIpe[i-1].baBody[iOff] & (byte)0x07) {                                  //          KID, ISAMID[4], (id-bits 18-16 are interesting)
                        case 4:                                                                     //                  100
                        case 5: sOid |= (short)0x2000; break;                                       //                  101 => +0x2000
                        case 6: sOid |= (short)0x6000; break;                                       //                  110 => +0x6000
                        case 7: sOid |= (short)0xE000; break;                                       //                  111 => +0xE000
                    }                                                                               //
                }                                                                                   //
                baOids[(i-1)*2    ] = (byte)(sOid >> 8);                                            //      Add it to of table under construction.
                baOids[(i-1)*2 + 1] = (byte)sOid;                                                   //
            }                                                                                       //
        }                                                                                           //
        return baOids;                                                                              // return the constructed table
    }


    // =============================================================================================    Dispatch (abstract implementation)

    // Commands
    public static final byte bOurCLA           	=  (byte)0x90;

    public static final byte bINS_Authenticate  =  (byte)0x10;
    public static final byte bINS_ReadIpe       =  (byte)0x12;
    public static final byte bINS_ReadVrg       =  (byte)0x14;
    public static final byte bINS_ReadLog       =  (byte)0x16;
    public static final byte bINS_UpdateIpe     =  (byte)0x18;
    public static final byte bINS_UpdateVrg     =  (byte)0x1A;
    public static final byte bINS_UpdateLog     =  (byte)0x1C;
    public static final byte bINS_UpdateDir     =  (byte)0x1E;
    public static final byte bINS_EndSession    =  (byte)0x20;
    public static final byte bINS_Reselect      =  (byte)0x22;

    // ========================================
    // Dispatch()
    //      process the APDU
    // ========================================
    protected byte[] Dispatch(byte[] baApdu) {                                                      // *** Card dispatch
        Log.d(TAG, "Dispatch");

        try {
            if (baApdu[ISO7816.OFFSET_CLA] != bOurCLA) {                                            // Must be our CLA
                return Response(SW.CLA_NOT_SUPPORTED);                                              //      nothing else is good enough.
            }                                                                                       //

            if (!fAuthenticated) {                                                                  // Not authenticated yet...
                switch (baApdu[ISO7816.OFFSET_INS]) {                                               //      Which INS do we want ?
                    case bINS_Authenticate:            DoAuthenticate(baApdu);  break;              //      supported
                    case bINS_ReadIpe:                 DoReadIpe(baApdu);       break;              //      ..
                    case bINS_ReadVrg:                 DoReadVrg(baApdu);       break;              //      ..
                    case bINS_ReadLog:                 DoReadLog(baApdu);       break;              //      ..
                    case bINS_Reselect:                DoReselect(baApdu);      break;              //      ..
                    case bINS_UpdateIpe:                                                            //      unsupported
                    case bINS_UpdateVrg:                                                            //      ..
                    case bINS_UpdateLog:                                                            //      ..
                    case bINS_UpdateDir:                                                            //      ..
                    case bINS_EndSession:                                                           //      ..
                        ApduException.Throw(SW.SECURITY_STATUS_NOT_SATISFIED);                      //
                    default:                                                                        //      all others
                        ApduException.Throw(SW.INS_NOT_SUPPORTED);                                  //          unrecognised
                }                                                                                   //
            }                                                                                       //
            else if (fAuthenticated) {                                                              // Authenticated, so Secure session active
                switch (baApdu[ISO7816.OFFSET_INS]) {                                               //      Which INS do we want ?
                    case bINS_ReadIpe:                 DoReadIpe(baApdu);      break;               //      supported
                    case bINS_ReadVrg:                 DoReadVrg(baApdu);      break;               //      ..
                    case bINS_ReadLog:                 DoReadLog(baApdu);      break;               //      ..
                    case bINS_Reselect:                DoReselect(baApdu);     break;               //      ..
                    case bINS_UpdateIpe:               DoUpdateIpe(baApdu);    break;               //      ..
                    case bINS_UpdateVrg:               DoUpdateVrg(baApdu);    break;               //      ..
                    case bINS_UpdateLog:               DoUpdateLog(baApdu);    break;               //      ..
                    case bINS_UpdateDir:               DoUpdateDir(baApdu);    break;               //      ..
                    case bINS_EndSession:              DoEndSession(baApdu);   break;               //      ..
                    case bINS_Authenticate:
                        ApduException.Throw(SW.SECURITY_STATUS_NOT_SATISFIED);                      //
                    default:                                                                        //      all others
                        ApduException.Throw(SW.INS_NOT_SUPPORTED);                                  //          unrecognised
                }                                                                                   //
            } else {
                ApduException.Throw(SW.SECURITY_STATUS_NOT_SATISFIED);
            }
        }
        catch (ApduExitException e) {
            return e.GetResponse();
        }
        catch (Exception e) {
            Log.d(TAG, "Dispatch: " + e.getMessage());
            return Response(SW.UNKNOWN);
        }
        return null;                                                                                // won't happen
    }


    // ##########################################################################
    // #  Function: DoAuthenticate
    // #        Authenticate APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoAuthenticate(byte[] baApdu) throws ApduExitException {                           // *** DoAuthenticate

        if (fAuthenticated) {												                        // Should not be permitted if we are already authenticated.
            ApduException.Throw(SW.SECURITY_STATUS_NOT_SATISFIED);							     	//      Not happy response
        }																							//

        if ((baApdu.length < ISO7816.OFFSET_LC) || (baApdu[ISO7816.OFFSET_LC] != 16)) {				// Auth expects 16 bytes from the ISAM.
            ApduException.Throw(SW.WRONG_LENGTH);													//      Not happy response
        }																							//

        byte[] baResponse;                                                                          // response to the challenge's response.
        try {
            if (shell.getKsc() == 0x03) {                                                           // CMD2 sytle authenticate.
                if ((fUsingPseudoShellUID) && (!fPseudoAuthenticated)) {                            // PseudoShell used and not yet authenticated
                    baResponse = GenSessionKey_Cmd2Style(baApdu, DesKeyPseudoA, DesKeyPseudoB);     // Authenticate (Exception on failure)
                    fPseudoAuthenticated = true;                                                    // PseudoAuth state.
                } else {                                                                            // Real Shell Auth
                    baResponse = GenSessionKey_Cmd2Style(baApdu, DesKeyA, DesKeyB);                 // Authenticate (Exception on failure)
                    fAuthenticated = true;                                                          // Auth state.
                    Hash.reset();                                                                   // initialise Apdu Hash
                }
            }
            else {                                                                                  //  Desfire style authentication
                 if ((fUsingPseudoShellUID) && (!fPseudoAuthenticated)) {                           // PseudoShell used and not yet authenticated
                    baResponse = GenSessionKey_Cmd7Style(baApdu, DesKeyPseudoA);                    // Authenticate (Exception on failure)
                    fPseudoAuthenticated = true;                                                    // PseudoAuth state.
                } else {                                                                            // Real Shell Auth
                    baResponse = GenSessionKey_Cmd7Style(baApdu, DesKeyA);                          // Authenticate (Exception on failure)
                    fAuthenticated = true;                                                          // Auth state.
                    Hash.reset();                                                                   // initialise Apdu Hash
                }
            }
            ApduException.Throw(baResponse, SW.NO_ERROR);											// Exit Happy.
        }
        catch (AuthenticationException e) {                                                         // Session key crypto failures end here.
            ApduException.Throw(SW.SECURITY_STATUS_NOT_SATISFIED);                                  //      Not happy response
        }                                                                                           //
        catch (ApduExitException e) {                                                               //
            throw e;                                                                                //
        }                                                                                           //
        catch (Exception e) {                                                                       // All other exceptions end here.
            Log.d(TAG, "DoAuthenticate: " + e.getMessage());                                        //       Leave a clue about what went wrong!
            ApduException.Throw(SW.UNKNOWN);                                                        //
        }
    }



    private	byte[] GenSessionKey_Cmd2Style(byte[] baApdu, SecretKey KeyA, SecretKey KeyB) 	                    // Verify PCD's response to our challenge
                                                                        throws AuthenticationException {        //      and generate our Response to their challenge
        try {                                                                                                   //
            Cip.init(Cipher.ENCRYPT_MODE, KeyA, NullIV);                                                        // Encrypt our challenge data
            byte[] baChallengeTemp = Cip.doFinal(baChallenge);                                                  //
                                                                                                                //
            if ( ! BytesMatch(baApdu, ISO7816.OFFSET_CDATA, baChallengeTemp, 0, bCHAL_SIZE))    {               // Compare with offered data (time invariance does not matter, its RND and unrepeatable)
                throw new AuthenticationException();                                                            // 		Exit Mr Grumpy.
            }                                                                                                   //
                                                                                                                //
            // Note: We only encrypt their data if they got ours right!											//
            Cip.init(Cipher.ENCRYPT_MODE, KeyB, NullIV);                                                        // POST's challenge
            byte[] baResponse = Cip.doFinal(baApdu, (short) (ISO7816.OFFSET_CDATA + bCHAL_SIZE), bCHAL_SIZE);   // Calculate our reply @0 <= Response data to caller
                                                                                                                //
            byte[] baSessionSeed = new byte[16];                                                                // Build the session key seed data
            System.arraycopy(baChallenge,                    4, baSessionSeed,  0, 4);    //      c4c5c6c7
            System.arraycopy(baApdu,      (ISO7816.OFFSET_CDATA + 12), baSessionSeed,  4, 4);    //              r1r2r3r4
            System.arraycopy(baChallenge,                    0, baSessionSeed,  8, 4);    //                      c1c2c3c4
            System.arraycopy(baApdu,      (ISO7816.OFFSET_CDATA +  8), baSessionSeed, 12, 4);    //                              r4r5r6r7
                                                                                                                //
            Cip.init(Cipher.ENCRYPT_MODE, KeyB, NullIV);                                                        //
            byte[] baSessionKey = Cip.doFinal(baSessionSeed);                                                   //      SK material = enc(Seed)
            SessionKey = new SecretKeySpec(baSessionKey,    "DESede");                                          //      create the SK
            Arrays.fill(baSessionKey, (byte)0);                                                                 // scrub the key material from the buffer before garbage collector sees it.
                                                                                                                //
            return baResponse;                                                                                  //
        }                                                                                                       //
        catch (AuthenticationException e) { throw e; }                                                          // Catch and re throw our crypto failures
        catch (Exception e) {                                                                                   // all crypto exceptions land here.
            Log.d(TAG, "GenSessionKey_Cmd2Style: " + e.getMessage());                                           //       Leave a clue about what went wrong!
            throw new AuthenticationException();                                                                //      but then throw a crypto cock-up exception.
        }                                                                                                       //
    }                                                                                                           //

    private	byte[] GenSessionKey_Cmd7Style(byte[] baApdu, SecretKey Key) throws AuthenticationException {       // Verify PCD's response to our challenge
                                                                                                                //      and generate our Response to their challenge
        try {                                                                                                   //
            short sByteCount = (short)0;
            Cip.init(Cipher.ENCRYPT_MODE, Key, NullIV);
            byte[] baRndA = Cip.doFinal(baApdu, ISO7816.OFFSET_CDATA, bCHAL_SIZE);                              // encrypt the PCD's response. Expecting [RndA :: Rot(RndB)]

            Cip.init(Cipher.ENCRYPT_MODE, Key, NullIV);
            byte[] baRotRnd = Cip.doFinal(baApdu, ISO7816.OFFSET_CDATA+8, bCHAL_SIZE);

            for (int i = 0; i < bCHAL_SIZE; i++) {                                                              // DESFires CBC is weird.
                baRotRnd[i] ^= baApdu[ISO7816.OFFSET_CDATA + i];                                                //
            }                                                                                                   //

            if (! BytesMatch(baRotRnd, 0, baChallenge, 1, bCHAL_SIZE-1)) {                                      // 7 out of 8 is good enough!
                throw new AuthenticationException();                                                            // 		Exit Mr Grumpy.
            }                                                                                                   //

            byte[] baSessionKey = new byte[16];                                                                 // Build the session key seed data
            System.arraycopy(baRndA,        0, baSessionKey,  0, 4);                                            //      a[7-4]
            System.arraycopy(baChallenge,   0, baSessionKey,  4, 4);                                            //            b[7-4]
            System.arraycopy(baRndA,        4, baSessionKey,  8, 4);                                            //                  a[3-0]
            System.arraycopy(baChallenge,   4, baSessionKey, 12, 4);                                            //                        b[3-0]
            SessionKey =  ConstructDesKey(baSessionKey);                                                        // create the SK
            Arrays.fill(baSessionKey, (byte)0);                                                                 // scrub the key material from the buffer before garbage collector sees it.

            baRotRnd[7] = baRndA[0];																	        // Rotate their RND
            System.arraycopy(baRndA, (short)1, baRotRnd, (short)0, (short)7);                                   //
            Cip.init(Cipher.ENCRYPT_MODE, Key, NullIV);                                                         //
            return Cip.doFinal(baRotRnd, 0, bCHAL_SIZE);                                                        // Response = encrypted PCD's rotated RndA

        }                                                                                                       //
        catch (AuthenticationException e) { throw e; }                                                          // Catch and re throw our crypto failures
        catch (Exception e) {                                                                                   // all crypto exceptions land here.
            Log.d(TAG, "GenSessionKey_Cmd2Style: " + e.getMessage());                                           //       Leave a clue about what went wrong!
            throw new AuthenticationException();                                                                //      but then throw a crypto cock-up exception.
        }                                                                                                       //
    }                                                                                                           //

    // ##########################################################################
    // #  Function: DoReadIpe
    // #        Read IPE APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoReadIpe(byte[] baApdu)  throws ApduExitException {                                                       // *** DoReadIpe
        int iIpeNo = baApdu[ISO7816.OFFSET_P1] & 0xFF;

        if ((iIpeNo == 0) ||                                                                        // Check != 0
            (iIpeNo > (shell.getE()-1)) ||                                                          //       <= E-1
            (baApdu[ISO7816.OFFSET_P2] != 0)) {                                                     //       P2 as prescribed, zero.
                ApduException.Throw(SW.INCORRECT_P1P2);                                             //      Oops. it's not
        }                                                                                           //

        if ((baApdu.length < 5) || (baApdu[ISO7816.OFFSET_LC] != 0)) {							    // length = all.
            ApduException.Throw(SW.WRONG_LENGTH);			                                        //
        }																                            //

        if (directory.E_Empty(iIpeNo)) {                                                            // Confirm the IPE is not empty
            ApduException.Throw(SW.RECORD_NOT_FOUND);                                               // Report "Record Not Found" as per spec.
        }

        int iIpeSize         = (aIpe[iIpeNo-1].baBody[0] & 0xfC);                                   // Size of IPE body + InstanceID + seal.
        byte[] baDeliverable = new byte[5 + iIpeSize + 16];                                         // Get the IPE

        System.arraycopy(directory.getEntry(iIpeNo), 0, baDeliverable, 0, 5);                                 // Dir entry +
        if (fAuthenticated) { System.arraycopy(aIpe[iIpeNo - 1].baBody, 0, baDeliverable, 5, iIpeSize+16);  } // Auth : Body + seal
        else                { System.arraycopy(aIpe[iIpeNo - 1].baBody, 0, baDeliverable, 5, iIpeSize);       //      : Body +
                              Arrays.fill(baDeliverable, 5+iIpeSize, 5+iIpeSize+16, (byte)0xff); }            //      :        redacted
        ResponseHashedIfNecessary(baDeliverable, SW.NO_ERROR);
    }

    private void  ResponseHashedIfNecessary(byte[] baBuff, short sStatusWord) throws ApduExitException {
        if (fAuthenticated) {
            Hash.update(baBuff);
            Hash.update((byte) (sStatusWord >> 8));
            Hash.update((byte) (sStatusWord & (byte) 0xFF));
        }
        ApduException.Throw(baBuff, sStatusWord);
    }


    // ##########################################################################
    // #  Function: DoReadVrg
    // #        Read VRG  APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoReadVrg(byte[] baApdu) throws ApduExitException {                                                       // *** DoReadVrg
        int iIpeNo = baApdu[ISO7816.OFFSET_P1] & 0xFF;

        if ((iIpeNo == 0) ||                                                                        // Check != 0
            (iIpeNo > (shell.getE()-1)) ||                                                          //       <= E-1
            (baApdu[ISO7816.OFFSET_P2] != 0)) {                                                     //       P2 as prescribed, zero.
                ApduException.Throw(SW.INCORRECT_P1P2);                                             //      Oops. it's not
        }                                                                                           //

        if ((baApdu.length < 5) || (baApdu[ISO7816.OFFSET_LC] != 0)) {							    // length = all.
            ApduException.Throw(SW.WRONG_LENGTH);			                                        //
        }																                            //

        if (directory.E_Empty(iIpeNo)) {                                                            // Confirm the IPE is not empty
            ApduException.Throw(SW.RECORD_NOT_FOUND);                                               // Report "Record Not Found" as per spec.
        }

        int iVrgSize         = (aVrg[iIpeNo-1].baBody[0] & 0xfC);                                   // Size of VRG body + InstanceID + seal.
        byte[] baDeliverable = new byte[5 + iVrgSize + 16];                                         // Get the VRG

        System.arraycopy(directory.getEntry(iIpeNo), 0, baDeliverable, 0, 5);                                 // Dir entry +
        if (fAuthenticated) { System.arraycopy(aVrg[iIpeNo - 1].baBody, 0, baDeliverable, 5, iVrgSize+16);  } // Auth : Body + seal
        else                { System.arraycopy(aVrg[iIpeNo - 1].baBody, 0, baDeliverable, 5, iVrgSize);       //      : Body +
                              Arrays.fill(baDeliverable, 5+iVrgSize, 5+iVrgSize+16, (byte)0xff); }            //      :        redacted
        ResponseHashedIfNecessary(baDeliverable, SW.NO_ERROR);
    }

    // ##########################################################################
    // #  Function: DoReadLog
    // #        Read TT-Log APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoReadLog(byte[] baApdu) throws ApduExitException {                                                       // *** DoReadLog
        if ((baApdu[ISO7816.OFFSET_P1] < 1) || (baApdu[ISO7816.OFFSET_P1] > 5)	||                  // record count, 1..5 == OK
            (baApdu[ISO7816.OFFSET_P2] != 0)) {							                            //     P2 must be zero
            ApduException.Throw(SW.INCORRECT_P1P2);                                                 //  Go home if we don't like it.
        }

        if ((baApdu.length < 5) || (baApdu[ISO7816.OFFSET_LC] != 0)) {							    // length = all.
            ApduException.Throw(SW.WRONG_LENGTH);			                                        //
        }																                            //

        short  sLen          = (short)(baApdu[ISO7816.OFFSET_P1]*0x30);                             // how many * record size
        byte[] baDeliverable = new byte[sLen];                                                      // Space needed

        System.arraycopy(TTLog.baBody, 0, baDeliverable, 0, sLen);                                  // Records copied
        ResponseHashedIfNecessary(baDeliverable, SW.NO_ERROR);
    }

    // ##########################################################################
    // #  Function: DoReselect
    // #        Reselection  APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoReselect(byte[] baApdu) throws ApduExitException {                                                      // *** DoReselect
        byte[] baA5Material;
        if (fUsingPseudoShellUID && !fPseudoAuthenticated) { baA5Material = FciBuildRandom();   }   // if pseudo shell and not pseudo authenticated, reissue the Random UID FCI
        else                                               { baA5Material = FciBuildReselect(); }   // else real shell or pseudo authenticated OK
        ApduException.Throw( WrapAsFci(null, baA5Material), SW.NO_ERROR);                           //
    }


    // ##########################################################################
    // #  Function: DoUpdateIpe
    // #        IPE write APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoUpdateIpe(byte[] baApdu) throws ApduExitException {                              // *** DoUpdateIpe

        int iIpeNo   = ((baApdu[ISO7816.OFFSET_P1] - 1) & 0xFF);                                    // IPE[1..E-1] ==> range 0..E-2
        int iDataLen = baApdu.length - ISO7816.OFFSET_CDATA;                                        // Payload size
        UpdateCheckIpeNo(baApdu, iIpeNo);                                                           // IPE# happy?
        UpdateCheckLength(baApdu, iDataLen);                                                        // Len happy ?
        UpdateCheckPassword(baApdu, iIpeNo);                                                        // Password Happy ?
        UpdateStoreHashAndExit(baApdu, aIpe[iIpeNo].baBody, iDataLen);                              // Copy new data to page and update the hash exit Happy exception.
    }

    private void UpdateCheckIpeNo(byte[] baApdu, int  iIpeNo) throws ApduExitException {            // check parameters and collect data
        if ((iIpeNo > (shell.getE()-2)) || (baApdu[ISO7816.OFFSET_P2] != 0)) {                      // Check IPE(1..E-1) & P2==0 before continuing
            ApduException.Throw(SW.INCORRECT_P1P2);                                                 //      Oops. it's not
        }                                                                                           //
    }                                                                                               //

    private void UpdateCheckLength(byte[] baApdu, int iLen) throws ApduExitException {              // check parameters and collect data
        if ((baApdu.length < (ISO7816.OFFSET_CDATA + bPWD_SIZE)) ||                                 // should be big enough to hold length at least
            (iLen != (bPWD_SIZE +(baApdu[ISO7816.OFFSET_CDATA + bPWD_SIZE] & 0xFC) + 16)) ||        // length should be pwd::ipe::seal
            ((baApdu[ISO7816.OFFSET_CDATA + bPWD_SIZE] & 0xFC) > sMAXIPE_SIZE) ) {                  // and <= limit to fit in an APDU
            ApduException.Throw(SW.WRONG_LENGTH);											        //
        }                                                                                           //
    }                                                                                               //

    private void UpdateCheckPassword(byte[] baBuff, int iSlot) throws ApduExitException {			// check parameters and collect data
        byte[] baTmp = Arrays.copyOfRange(baBuff, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_CDATA + bPWD_SIZE);                 // Just the pwd bit
        if (! MessageDigest.isEqual(baTmp, aPassword[iSlot].baBody)) {                              // Time invariant check of the password.
            ApduException.Throw(SW.AUTHENTICATION_FAILURE);                                         //      Fail. Bad luck!
        }                                                                                           //
    }                                                                                               //

    private void UpdateStoreHashAndExit(byte[] baBuff,  byte[] baPage, int iLen) throws ApduExitException {
        System.arraycopy(baBuff, ISO7816.OFFSET_CDATA + bPWD_SIZE,                                  // source,          // Copy new contents to the page
                         baPage, 0,                                                                 // destination      //
                         iLen - bPWD_SIZE);                                                         // size.            //
        Hash.update(baBuff, 0, ISO7816.OFFSET_CDATA + iLen);                                        // Update the Hash  // Apdu
        Hash.update((byte) (SW.NO_ERROR >> 8));                                                     //                  // and it's SW
        Hash.update((byte) (SW.NO_ERROR & (byte) 0xFF));                                            //                  //
        ApduException.Throw(SW.NO_ERROR);                                                           // Happy ending.
    }



    // ##########################################################################
    // #  Function: DoUpdateVrg
    // #        VRG Write APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoUpdateVrg(byte[] baApdu) throws ApduExitException {                              // *** DoUpdateVrg
        int iIpeNo   = ((baApdu[ISO7816.OFFSET_P1] - 1) & 0xFF);                                    // IPE[1..E-1] ==> range 0..E-2
        int iDataLen = baApdu.length - ISO7816.OFFSET_CDATA;                                        // Payload size
        UpdateCheckIpeNo(baApdu, iIpeNo);                                                           // IPE# happy?
        UpdateCheckLength(baApdu, iDataLen);                                                        // Len happy ?
        UpdateCheckPassword(baApdu, iIpeNo);                                                        // Password Happy ?
        UpdateStoreHashAndExit(baApdu, aVrg[iIpeNo].baBody, iDataLen);                              // Copy new data to page and update the hash exit Happy exception.
    }


    // ##########################################################################
    // #  Function: DoUpdateLog
    // #        TT-Log Write APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoUpdateLog(byte[] baApdu) throws ApduExitException, Exception {                   // *** DoUpdateLog
        int iIpeNo   = shell.getE() -1;                                                             // IPE # E is reserved for the log
        int iDataLen = baApdu.length - ISO7816.OFFSET_CDATA;                                        // Payload size
        if ((iDataLen < bPWD_SIZE) || (bPWD_SIZE + 0x30 < iDataLen)) {                              // length should be pwd::logRecord[..30]
            ApduException.Throw(SW.WRONG_LENGTH);                                                   //      Oops. it's not
        }                                                                                           //
        UpdateCheckPassword(baApdu, iIpeNo);                                                        // Password Happy ?
        System.arraycopy(TTLog.baBody, 0, TTLog.baBody, 0x30, TTLog.baBody.length - 0x30);          // Shuffle old records 0..4 to new 1..5
        UpdateStoreHashAndExit(baApdu, TTLog.baBody, iDataLen);                                     // Squeeze in the new record at #0 &  hash exit Happy exception.
    }

    // ToDo: test when the body < password length

    // ##########################################################################
    // #  Function: DoUpdateDir
    // #        Directory Write APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoUpdateDir(byte[] baApdu) throws ApduExitException, Exception {                   // *** DoUpdateDir
        int iIpeNo   = shell.getE();                                                                // IPE # E+1 is reserved for the Directory
        int iDataLen = baApdu.length - ISO7816.OFFSET_CDATA;                                        // Payload size
        if (iDataLen != bPWD_SIZE + directory.getLength()) {                                        // length should be pwd::logRecord[30]
            ApduException.Throw(SW.WRONG_LENGTH);                                                   //      Oops. it's not
        }                                                                                           //

        UpdateCheckPassword(baApdu, iIpeNo);                                                        // Password Happy ?
        directory.Update(baApdu, bPWD_SIZE + ISO7816.OFFSET_CDATA);                                 //
        Hash.update(baApdu, 0, baApdu.length);                                                      // Update the Hash  // Apdu
        Hash.update((byte) (SW.NO_ERROR >> 8));                                                     //                  // and it's SW
        Hash.update((byte) (SW.NO_ERROR & (byte) 0xFF));                                            //                  //
        ApduException.Throw(SW.NO_ERROR);                                                           // Happy ending.
    }


    // ##########################################################################
    // #  Function: DoEndSession
    // #        Commit changes and session end APDU manager.
    // #
    // #  Parameters:
    // #        byte[] baApdu - The APDU sent by the PCD.
    // #
    // #  Returns by ApduExitException
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoEndSession(byte[] baApdu) throws ApduExitException, Exception {                  // *** DoEndSession
        fAuthenticated = false;                                                                     // Always terminate the SM now this has been called.

        if ((baApdu[ISO7816.OFFSET_P1] != 0) || (baApdu[ISO7816.OFFSET_P2] != 0)) {                 //  P1 & P2 should = 0
            ApduException.Throw(SW.INCORRECT_P1P2);                                                 //
        }
        if (baApdu[ISO7816.OFFSET_LC] != bCSS_SIZE) {                                               // Check Len = sig size.
            ApduException.Throw(SW.WRONG_LENGTH);                                                   //
        }                                                                                           //

        byte[] baMac = Hash.digest();		                                                        // This is our Hash of the earlier APDUs

        if ((baMac.length % 8) != 0) {                                                              // Padded if the MAC is not block of 8
            baMac = Arrays.copyOfRange(baMac, 0, ((baMac.length + 7) / 8) * 8);                     //
        }                                                                                           //

        Sig.init(Cipher.ENCRYPT_MODE, SessionKey, new IvParameterSpec(new byte[8]));                // We do Sig as a DES MAC
        byte[] baSig = Sig.doFinal(baMac);                                                          // Calculate the MAC. it's the last block here
        if (!BytesMatch(baApdu, ISO7816.OFFSET_CDATA, baSig, baSig.length - 8, 8)) {                // Check we agree with the caller.
            ApduException.Throw(SW.AUTHENTICATION_FAILURE);                                         //      Not happy!
        }                                                                                           //

        Sig.init(Cipher.ENCRYPT_MODE, SessionKey, new IvParameterSpec(new byte[8]));                //
        baCSS = Sig.doFinal(baSig, baSig.length - bCSS_SIZE, bCSS_SIZE);                            // CSS response = enc(TS)
        incTsn();																	                // Transaction number ++
        ImageSave();
        ApduException.Throw(baCSS, SW.NO_ERROR);
    }


// ==========================================================================================
// Because a phone keeps this in RAM and writes it to the file at the same time as the sectors
// there is no need to juggle the free page mechanism.
// Pages can be written directly at their own index.
//
// Similarly, data integrity is part and parcel of the image preservation/recovery in
// the VCard class. No need for the MMMT crc field either.
//
// So, Sector count = 3 + (2*E-1)
//     Shell    = sector 0              // index since shell sector is omitted
//     Ipe/Vrg  = sector 1-E-1          // 0..E-2
//     Log      = sector E              // E-1
//     Dir      = sector E+1            // E
// ==========================================================================================

    private  void arrayCopy(byte[] baSrc, byte[] baDst) {       // Local Array copy utility
        System.arraycopy(baSrc, 0, baDst, 0, Math.min(baSrc.length, baDst.length));
    }

    private  byte[] makeSector(byte[] baV) {
        if (baV.length == sPAGE_SIZE) return baV;
        else return Arrays.copyOf(baV, sPAGE_SIZE);
    }


    public void   setCCS(byte[] baV)                  { arrayCopy(baV, baCSS);                  }   // CCS accessors
    public void   getCCS(byte[] baV)                  { arrayCopy(baCSS, baV);                  }
    public byte[] getCCS()                            { return baCSS;                           }
    public void   setTsn(int i)                       { iTsn = i;                               }  // iTsn accessors
    public int    getTsn()                            { return iTsn;                            }
    public void   incTsn()                            { iTsn++;                                 }

    //public void   setDir(byte[] baV)              { directory.Set(baV);                         }   // Dir accessors
    //public void   getDir(byte[] baV)              { arrayCopy(directory.Get(), baV);            }
    //public byte[] getDir()                        { return directory.Get();                     }
    public void   setLog(byte[] baV)              { TTLog.baBody = makeSector(baV);             }  // Log accessors
    public void   getLog(byte[] baV)              { arrayCopy(TTLog.baBody, baV);               }
    public byte[] getLog()                        { return TTLog.baBody;                        }
    public void   setIpe(int iIndex, byte[] baV)  { aIpe[iIndex-1].baBody = makeSector(baV);    }  // Ipe  accessors
    public void   getIpe(int iIndex, byte[] baV)  { arrayCopy(aIpe[iIndex-1].baBody, baV);      }
    public byte[] getIpe(int iIndex)              { return aIpe[iIndex-1].baBody;               }
    public void   setVrg(int iIndex, byte[] baV)  { aVrg[iIndex-1].baBody = makeSector(baV);    }  // VrgA accessors
    public void   getVrg(int iIndex, byte[] baV)  { arrayCopy(aVrg[iIndex-1].baBody, baV);      }
    public byte[] getVrg(int iIndex)              { return aVrg[iIndex-1].baBody;               }
    public void   setPwd(int i, byte[] baV)       { aPassword[i].baBody = baV;                  }


    // ToDo: do we want to provide password accessors here to mask the array/sector displacement from the caller?




}