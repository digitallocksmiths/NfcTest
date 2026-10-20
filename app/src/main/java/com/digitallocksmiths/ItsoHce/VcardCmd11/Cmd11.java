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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


public class Cmd11 extends VCard {
    private static final String TAG = "Cmd11";

    private static final byte  bCHAL_SIZE       =   8;                                              // Size of Random Challenge Data


    private static final short sPAGE_SIZE         = 256;                                            // size of sector (IPE or VRG records)
    private static class Sector   { byte[] baBody = new byte[sPAGE_SIZE]; }

    private static final byte  bPWD_SIZE        =   8;                                              // Size of Password Data
    private static class Password { byte[] baBody = new byte[bPWD_SIZE];  }



    // ==========================================================================
    // Clear on reset 'RAM' variables

    public byte[]  baChallenge          = new byte[bCHAL_SIZE];
    public byte[]  baChallengeTemp      = new byte[bCHAL_SIZE];
    public boolean fAuthenticated       = false;                                                    // Bool vars
    public boolean fPseudoAuthenticated = false;
    public short   sFciStart            = 0;                                                        // Short vars
    public short   sFciA5LenOffset      = 0;
    // public short   sAllocated           = 0;

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

    private byte[]       baCSS       = new byte[8];                                                 // Commit Confirmation Signature
    private int          iTsn;                                                                      // Transaction Sequence Number;

    // not needed? private Sector   Shell;                                                          //     0: Shell
    private Sector[]     aIpe;                                                                      // 1-E-1: Ipes      (0..E-2)
    private Sector[]     aVrg;                                                                      // 1-E-1: Vrgs      (1..E-2)
    private Sector       TTLog;                                                                     //     E: Log       (E-1)
    private Directory    directory;                                                                 //   E+1: Directory (E)
    private Password[]   aPassword;                                                                 // 1-E+1: Password  (0-E)


    private SecretKey DesKeyA;
    private SecretKey DesKeyB;
    private SecretKey DesKeyPseudoA;
    private SecretKey DesKeyPseudoB;

    private static final SecureRandom Rng = new SecureRandom();                                     // Shared Random generator.

    public  static final Cipher       Cip;                                                          // challenge processor/SK generator.
    static {
        Cipher cipherInstance = null;
            try {
                cipherInstance = Cipher.getInstance("DESede/CBC/NoPadding");           // Initialize Cip as Triple DES in CBC mode with no padding
            }  catch (java.security.NoSuchAlgorithmException e) {
                    Log.e(TAG, "NoSuchAlgorithmException: DESede/CBC/NoPadding not found", e);
            } catch (NoSuchPaddingException e) {
                    Log.e(TAG, "NoSuchPaddingException: NoPadding not supported", e);
            }
            Cip = cipherInstance;
    }

//  public static Checksum      Crc;                                                                //        CRC resource.
//  public static Signature     Sig;                                                                // 		  MAC verifyer/generator.
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

        // ToDo: Do we need to allocate the space.
        // Deserialize will create and assign byte[]s.
        // Just need to ensure JSON parser fills the correct size.
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
        // ToDo: Deserialize the image here.
        try {
            baCSS = VCard.DeserializeByteArray(buffer);
            iTsn = buffer.getInt();
            baAid = DeserializeByteArray(buffer);
            mAuthDesKeyA = DeserializeByteArray(buffer);
            mAuthDesKeyB = DeserializeByteArray(buffer);
            mAuthPseudoKeyA = DeserializeByteArray(buffer);
            mAuthPseudoKeyB = DeserializeByteArray(buffer);
            baPseudoShell = DeserializeByteArray(buffer);
            baUID = DeserializeByteArray(buffer);
            baPseudoUID = DeserializeByteArray(buffer);
            baCapabillities = DeserializeByteArray(buffer);
            baAuthKasParams = DeserializeByteArray(buffer);
            for (Sector sector : aIpe) {
                sector.baBody = DeserializeByteArray(buffer);
            }
            for (Sector sector : aVrg) {
                sector.baBody = DeserializeByteArray(buffer);
            }
            TTLog.baBody = DeserializeByteArray(buffer);
            directory = new Directory(shell, DeserializeByteArray(buffer));
            for (Password password : aPassword) {
                password.baBody = DeserializeByteArray(buffer);
            }

            if ((mAuthDesKeyA    != null)  && (mAuthDesKeyA.length    > 0)) { DesKeyA       = new SecretKeySpec(mAuthDesKeyA,    "DESede"); }
            if ((mAuthDesKeyB    != null)  && (mAuthDesKeyB.length    > 0)) { DesKeyB       = new SecretKeySpec(mAuthDesKeyB,    "DESede"); }
            if ((mAuthPseudoKeyA != null)  && (mAuthPseudoKeyA.length > 0)) { DesKeyPseudoA = new SecretKeySpec(mAuthPseudoKeyA, "DESede"); }
            if ((mAuthPseudoKeyB != null)  && (mAuthPseudoKeyB.length > 0)) { DesKeyPseudoB = new SecretKeySpec(mAuthPseudoKeyB, "DESede"); }

        }
        catch (VirtualCardException e) {
            Log.d(TAG, "Corrupt Image file");
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

        if ((mAuthDesKeyA    != null)  && (mAuthDesKeyA.length    > 0)) { DesKeyA       = new SecretKeySpec(mAuthDesKeyA,    "DESede"); }
        if ((mAuthDesKeyB    != null)  && (mAuthDesKeyB.length    > 0)) { DesKeyB       = new SecretKeySpec(mAuthDesKeyB,    "DESede"); }
        if ((mAuthPseudoKeyA != null)  && (mAuthPseudoKeyA.length > 0)) { DesKeyPseudoA = new SecretKeySpec(mAuthPseudoKeyA, "DESede"); }
        if ((mAuthPseudoKeyB != null)  && (mAuthPseudoKeyB.length > 0)) { DesKeyPseudoB = new SecretKeySpec(mAuthPseudoKeyB, "DESede"); }
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
        sFciStart            = 0;
        sFciA5LenOffset      = 0;
        //sAllocated           = 0;

    }

    // =============================================================================================    Select (abstract implementation)
    // ========================================
    // Select()
    //      construct and return the FCI.A5's contents
    // ========================================
    public byte[] Select() {                                                                        // *** Card select
        Log.d(TAG, "Select");                                                                  //
        try {                                                                                       //
            Reset();                                                                                // Clear on reset//select variables initialized.
        }                                                                                           //
        catch (VirtualCardException e) {                                                            //
            Log.d(TAG, "Select: + " + e.getMessage() );                                        // report trouble if needed
            return new byte[] { (byte)0x80, 1, 11};                                                 //
        }                                                                                           //
                                                                                                    //
        if (baPseudoShell != null && baPseudoShell.length > 0) { return FciBuildRandom(); }         // Build FCI for random  UID host
        else                                                   { return FciBuildStatic(); }         //               static  UID host
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
        tagList.add(TlvBuildPrimitive(bTagShell,        baShell));
        tagList.add(TlvBuildPrimitive(bTagCapabilities, baCapabillities));
        tagList.add(TlvBuildPrimitive(bTagDirectory,    directory.Get()));
        tagList.add(TlvBuildPrimitive(bTagOidList,      ConstructOids()));
        tagList.add(TlvBuildPrimitive(bTagCss,          baCSS));
        tagList.add(TlvBuildPrimitive(bTagChallenge,    ConstructChallenge(DesKeyA)));
        tagList.add(TlvBuildPrimitive(bTagAuth,         baAuthKasParams));
        return FciBuild(tagList);
    }

    private byte[] FciBuildRandom() {                                                               // *** Random UID FCI
        ArrayList<byte[]> tagList = new ArrayList<>();
        tagList.add(TlvBuildPrimitive(bTagShell,        baPseudoShell));
        tagList.add(TlvBuildPrimitive(bTagCapabilities, baCapabillities));
        tagList.add(TlvBuildPrimitive(bTagCss,          baCSS));
        tagList.add(TlvBuildPrimitive(bTagChallenge,    ConstructChallenge(DesKeyPseudoA)));
        tagList.add(TlvBuildPrimitive(bTagPseudoUid,    baPseudoUID));
        tagList.add(TlvBuildPrimitive(bTagAuth,         baAuthKasParams));
        return FciBuild(tagList);
    }

    private byte[] FciBuildReselect() {                                                             // *** Reselection FCI
        ArrayList<byte[]> tagList = new ArrayList<>();
        tagList.add(TlvBuildPrimitive(bTagShell,        baShell));
        tagList.add(TlvBuildPrimitive(bTagDirectory,    directory.Get()));
        tagList.add(TlvBuildPrimitive(bTagOidList,      ConstructOids()));
        tagList.add(TlvBuildPrimitive(bTagChallenge,    ConstructChallenge(DesKeyA)));
        tagList.add(TlvBuildPrimitive(bTagStaticUid,    baUID));
        tagList.add(TlvBuildPrimitive(bTagAuth,         baAuthKasParams));
        return FciBuild(tagList);
    }

    private byte[] FciBuild(ArrayList<byte[]> tagList) {                                            // *** FciBuild
        int iLen = 0;                                                                               //      TLV element list into byte[]
        for (byte[] baTt : tagList) { iLen += baTt.length; }                                        //      calculate space to return all
        byte[] baA5contents = new byte[iLen];                                                       //      create that much  space
        int iOffset = 0;                                                                            //
        for (byte[] baTt : tagList) {                                                               //      copy each tlv into this space
            System.arraycopy(baTt, 0, baA5contents, iOffset, baTt.length);                   //
            iOffset += baTt.length;                                                                 //
        }                                                                                           //
        return baA5contents;                                                                        // return with a job done well!
    }                                                                                               //

    private byte[] TlvBuildPrimitive(byte bTag, byte[] baV) {                                       // *** TlvBuildPrimitive
        byte[] baTlv;                                                                               //      make a ptomative T.L.V.
        if (baV.length <= 127) { baTlv = new byte[2 + baV.length]; }                                //      ? length > 127 needs '1':: len
        else                   { baTlv = new byte[2 + 1 + baV.length]; }                            //        length < 128 is just a simple length
        int iOffset = 0;                                                                            //        Note: Max length catered for here is 255!
        baTlv[iOffset++] = bTag;                                                                    //      insert T
        if (baV.length > 127) { baTlv[iOffset++] = 1; }                                             //      insert L
        baTlv[iOffset++] = (byte)baV.length;                                                        //
        System.arraycopy(baV, 0, baTlv, iOffset, baV.length);                                //      insert V
        return baTlv;                                                                               // return. job done.
    }

    private byte[] ConstructChallenge(SecretKey key) {                                              // *** ConstructChallenge
        Rng.nextBytes(baChallenge);                                                                 //  make random challenge
                                                                                                    //
        if (shell.getKsc() == 0x04) {                                                               // ? DESFire style
            try {                                                                                   //
                Cip.init(Cipher.ENCRYPT_MODE, key);                                                 //      it needs to be encrypted
                baChallengeTemp = Cip.doFinal(baChallenge);                                         //
            } catch (Exception e) {                                                                 //
                Log.e(TAG, "ConstructChallenge: Encryption failed: " + e.getMessage());        //       report problems.
                System.arraycopy(baChallenge, 0, baChallengeTemp, 0, bCHAL_SIZE);    //
            }                                                                                       //
        }                                                                                           //
        else {                                                                                      // ? CMD2 style
            System.arraycopy(baChallenge, 0, baChallengeTemp, 0, bCHAL_SIZE);        //
        }                                                                                           //
                                                                                                    //
        return baChallengeTemp;                                                                     // That's all folks.
    }                                                                                               //

    private byte[] ConstructOids() {                                                                // *** ConstructOids
        byte[] baOids = new byte[2 * (shell.getE()-1)];                                             //      make a list of the IPE owners.
        for (int i = 1; i < shell.getE()-1; i++) {                                                  //      One enty for each E/possible IPE
            short sOid = 0;                                                                         //
            if (directory.E_Empty(i)) {                                                        //      used?
                sOid = directory.E_Oid(i);                                                         //      get the OID (13 bits from directory.E[i])
                if (directory.E_Ext(i)) {                                                             //      Do we need to extend the OID by the ISAM fudge factor?
                    int iOff = 2 + aIpe[i-1].baBody[0] & (byte)0xFC;                                //          Top bits are collected from the IPE's instance ID
                    switch (aIpe[i-1].baBody[iOff] & (byte)0x07) {                                  //          KID, ISAMID[4], (id-bits 18-16 are interesting)
                        case 4:                                                                     //                  100
                        case 5: sOid |= (short)0x2000; break;                                       //                  101 => +0x2000
                        case 6: sOid |= (short)0x6000; break;                                       //                  110 => +0x6000
                        case 7: sOid |= (short)0xE000; break;                                       //                  111 => +0xE000
                    }                                                                               //
                }                                                                                   //
                baOids[(i-1)*2    ] = (byte)(sOid >> 8);                                            //      Add it to of table uder construction.
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

        if (baApdu[ISO7816.OFFSET_CLA] != bOurCLA) {                                                // Must be out CLA
            return Response(SW.CLA_NOT_SUPPORTED);                                                  //      nothing else is good enough.
        }                                                                                           //

        if (!fAuthenticated) {                                                                      // Not authenticated yet...
            switch (baApdu[ISO7816.OFFSET_INS]) {                                                   //      Which INS do we want ?
                case bINS_Authenticate: return DoAuthenticate(baApdu);                              //      supported
                case bINS_ReadIpe:      return DoReadIpe(baApdu);                                   //      ..
                case bINS_ReadVrg:      return DoReadVrg(baApdu);                                   //      ..
                case bINS_ReadLog:      return DoReadLog(baApdu);                                   //      ..
                case bINS_Reselect:     return DoReselect(baApdu);                                  //      ..
                case bINS_UpdateIpe:                                                                //      unsuported
                case bINS_UpdateVrg:                                                                //      ..
                case bINS_UpdateLog:                                                                //      ..
                case bINS_UpdateDir:                                                                //      ..
                case bINS_EndSession:   return Response(SW.SECURITY_STATUS_NOT_SATISFIED);          //      ..
                default:                return Response(SW.INS_NOT_SUPPORTED);                      //      unrecognised
            }                                                                                       //
        }                                                                                           //
        else if (fAuthenticated) {                                                                  // Authenticated, so Secure session active
            switch (baApdu[ISO7816.OFFSET_INS]) {                                                   //      Which INS do we want ?
                case bINS_Authenticate: return Response(SW.CONDITIONS_NOT_SATISFIED);               //      out of context
                case bINS_ReadIpe:      return DoReadIpe(baApdu);                                   //      supported
                case bINS_ReadVrg:      return DoReadVrg(baApdu);                                   //      ..
                case bINS_ReadLog:      return DoReadLog(baApdu);                                   //      ..
                case bINS_Reselect:     return DoReselect(baApdu);                                  //      ..
                case bINS_UpdateIpe:    return DoUpdateIpe(baApdu);                                 //      ..
                case bINS_UpdateVrg:    return DoUpdateVrg(baApdu);                                 //      ..
                case bINS_UpdateLog:    return DoUpdateLog(baApdu);                                 //      ..
                case bINS_UpdateDir:    return DoUpdateDir(baApdu);                                 //      ..
                case bINS_EndSession:   return DoEndSession(baApdu);                                //      ..
                default:                return Response(SW.INS_NOT_SUPPORTED);                      //      unrecognised
            }                                                                                       //
        }
        else {
            return Response(SW.SECURITY_STATUS_NOT_SATISFIED);
        }
    }


    private byte[] DoAuthenticate(byte[] baApdu) {                                                  // *** DoAuthenticate
        // ToDo: Implement Authentication
        return Response(SW.UNKNOWN);
    }

    private byte[] DoReadIpe(byte[] baApdu) {                                                       // *** DoReadIpe
        // ToDo: Implement DoReadIpe
        return Response(SW.UNKNOWN);
    }

    private byte[] DoReadVrg(byte[] baApdu) {                                                       // *** DoReadVrg
        // ToDo: Implement DoReadVrg
        return Response(SW.UNKNOWN);
    }

    private byte[] DoReadLog(byte[] baApdu) {                                                       // *** DoReadLog
        // ToDo: Implement DoReadLog
        return Response(SW.UNKNOWN);
    }

    private byte[] DoReselect(byte[] baApdu) {                                                      // *** DoReselect
        // ToDo: Implement DoReselect
        return Response(SW.UNKNOWN);
    }


    private byte[] DoUpdateIpe(byte[] baApdu) {                                                     // *** DoUpdateIpe
        // ToDo: Implement DoUpdateIpe
        return Response(SW.UNKNOWN);
    }


    private byte[] DoUpdateVrg(byte[] baApdu) {                                                     // *** DoUpdateVrg
        // ToDo: Implement DoUpdateVrg
        return Response(SW.UNKNOWN);
    }


    private byte[] DoUpdateLog(byte[] baApdu) {                                                     // *** DoUpdateLog
        // ToDo: Implement DoUpdateLog
        return Response(SW.UNKNOWN);
    }


    private byte[] DoUpdateDir(byte[] baApdu) {                                                     // *** DoUpdateDir
        // ToDo: Implement DoUpdateDir
        return Response(SW.UNKNOWN);
    }


    private byte[] DoEndSession(byte[] baApdu) {                                                    // *** DoEndSession
        // ToDo: Implement DoEndSession
        return Response(SW.UNKNOWN);
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

    public void   setDir(byte[] baV)              { directory.Set(baV);                         }   // Dir accessors
    public void   getDir(byte[] baV)              { arrayCopy(directory.Get(), baV);            }
    public byte[] getDir()                        { return directory.Get();                     }
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