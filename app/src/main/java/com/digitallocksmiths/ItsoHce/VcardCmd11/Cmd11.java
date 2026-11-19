package com.digitallocksmiths.ItsoHce.VcardCmd11;

// ToDo:    1:  Application Asymmetric key pair & API call to get public.
//          2:  Build in Public key of the management authority.
//          3:  Import JSON to take extended card image.
//          3a:     Include an optional graphic-image for use in GUI card select
//          3b:     Encrypted card Image using the Application's asymmetric key.
//          3c:     Signed card Image using the management authority's asymmetric key.
//          4:  Export JSON card image.
//          4a:     Clear text if keys are excluded.
//          4b:     full image encrypted for the management authority and signed by the Application's private key.
//          5:  API extension
//          5a:     Get IPEs, VRGs and LOGs for local GUI rendering.
//          5b:     Get card graphic-image for local GUI rendering.
//          5c:     Delete message, (signed by management authority.) to remove images.


// ##########################################################################
// ToDo: generate tests for
//      A: Max size IPE.
//      B: Case of each command i.e.  Lc/Le used appropriately
//      C: Can manage mone- 9000 SW12 responses.


import android.util.Log;

import com.digitallocksmiths.ItsoHce.Apdu;
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

    // CONSTANTS
    private static final int    iCHALLENGE_SIZE =   8;                                              // The size of the Mutual Authenticate random challenge
    private static final int    iSECTOR_SIZE    = 256;                                              // The size of a storage block used for IPEs, VRGs, LOGs and Directory
    private static final int    iPASSWORD_SIZE  =   8;                                              // Size of Password Data
    // ToDo: ITSO ref is 228. Who's right?
    public  static final int    iIPE_MAXSIZE    = (255 - iPASSWORD_SIZE - 16);                      // pwd[8] :: Ipe[x] :: Seal[16]  =< 255 bytes.
    public  static final int    iCSS_SIZE       =  8;                                               // Commit Confirmation Signature Size.

    private static class Sector   { byte[] baBody   = new byte[iSECTOR_SIZE]; }                     // Sector is a storage unit. Java is messy with arrays of arrays (hence this)
    private static class Password { byte[] baBody   = new byte[iPASSWORD_SIZE];  }                  // Passwords. same again and just as many.

    // ==========================================================================
    // Clear on reset 'RAM' variables

    public byte[]  baChallenge           = new byte[iCHALLENGE_SIZE];                               // Mutual Authenticat Challenge (random data)
    public byte[]  baChallengeTemp       = new byte[iCHALLENGE_SIZE];                               // Holds the mangled Challenge delivered to the IFD.
    private sbool  sfAuthenticated       = sbool.False;                                             // secure boolean flag vars. Are we fully authenticated ?
    private sbool  sfPseudoAuthenticated = sbool.False;                                             //                           Are we authenticated against the pseudo UID/Shell ?
    private sbool  sfUsingPseudoShellUID = sbool.False;                                             //                           Should we be expecting a pseudo UID/Shell ?

    // ==========================================================================
    // NV variables
    //      This is the stuff we preserve. In a card it would be in NVM
    //      Originally delivered via Import JSON. Thereafter Load/SaveImage.
    //

    private byte[] mAuthDesKeyA;                                                                    // Authentication key, sets up the session key
    private byte[] mAuthDesKeyB;                                                                    // KSC3 uses a second Auth key. This is it.
    private byte[] mAuthPseudoKeyA;                                                                 // Same again but for the pseudo UID/Shell
    private byte[] mAuthPseudoKeyB;                                                                 //
    private byte[] baPseudoShell;                                                                   // Contents of the pseudo shell (or null/empty for static uid)
    private byte[] baPseudoUID;                                                                     // the perso assigned UID for pseudo shell authentication
    private byte[] baCapabillities;                                                                 // what command set is supported. (Only 00 is defined in V2.1.5)
    private byte[] baAuthKasParams;                                                                 // Was KAS values are used in Begin and ExtAuth.

    private byte[]       baCSS       = new byte[iCSS_SIZE];                                         // Commit Confirmation Signature
    private int          iTsn;                                                                      // Transaction Sequence Number;

    // not needed? private Sector   Shell;                                                          //     0: Shell
    private Sector[]     aIpe;                                                                      // 1-E-1: Ipes      (0..E-2)
    private Sector[]     aVrg;                                                                      // 1-E-1: Vrgs      (1..E-2)
    private Sector       TTLog;                                                                     //     E: Log       (E-1)
    private Directory    directory;                                                                 //   E+1: Directory (E)
    private Password[]   aPassword;                                                                 // 1-E+1: Password  (0-E)


// ==========================================================================
// Working variables
//

    private       SecretKey       DesKeyA;                                                          // initialized on image load.
    private       SecretKey       DesKeyB;                                                          //
    private       SecretKey       DesKeyPseudoA;                                                    //
    private       SecretKey       DesKeyPseudoB;                                                    //

    private       SecretKey       SessionKey;                                                       // ephemeral session key.
    private final SecureRandom    Rng;                                                              // Random generator.
    public  final Cipher          Cip;                                                              // challenge processor/SK generator.
    private final MessageDigest   Hash;                                                             // session MAC generator
    private final IvParameterSpec NullIV = new IvParameterSpec(new byte[8]);                        // IV = 0.0.0.0.0.0.0.0

    public final  Cipher          Sig;                                                              // MAC verifyer/generator. (In Java, DES needs to use a Cipher and use the chained IV)

    // ========================================
    // Constructor
    //
    // ========================================
    public Cmd11(byte[] baShell)  throws VCard.VirtualCardException {
        super(baShell);
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
    }                                                                                               // Exit with all space allocated, to be populated later.


    // ========================================
    // ImageGetSize()
    //    Return the size of the serialized image in bytes.
    // ========================================
    protected int   ImageGetSize() {                                                                // subclasses indicate their own storage volume requirements
        Log.d(TAG, "ImageGetSize");
        return  SerializeOverhead + baCSS.length +
                4   /* sizeof(iTsn) */  +
                SerializeOverhead + mAuthDesKeyA.length +
                SerializeOverhead + mAuthDesKeyB.length +
                SerializeOverhead + mAuthPseudoKeyA.length +
                SerializeOverhead + mAuthPseudoKeyB.length +
                SerializeOverhead + baPseudoShell.length +
                SerializeOverhead + baPseudoUID.length +
                SerializeOverhead + baCapabillities.length +
                SerializeOverhead + baAuthKasParams.length +
               (SerializeOverhead + iSECTOR_SIZE)  * aIpe.length +
               (SerializeOverhead + iSECTOR_SIZE)  * aVrg.length +
                SerializeOverhead + iSECTOR_SIZE  /* TTLog */ +
                SerializeOverhead + directory.getLength() +
               (SerializeOverhead + iPASSWORD_SIZE)   * aPassword.length;
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
            //baAid              = DeserializeByteArray(buffer);
            mAuthDesKeyA       = DeserializeByteArray(buffer);
            mAuthDesKeyB       = DeserializeByteArray(buffer);
            mAuthPseudoKeyA    = DeserializeByteArray(buffer);
            mAuthPseudoKeyB    = DeserializeByteArray(buffer);
            baPseudoShell      = DeserializeByteArray(buffer);
            //baUID              = DeserializeByteArray(buffer);
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
        SerializeByteArray(buffer, mAuthDesKeyA);
        SerializeByteArray(buffer, mAuthDesKeyB);
        SerializeByteArray(buffer, mAuthPseudoKeyA);
        SerializeByteArray(buffer, mAuthPseudoKeyB);
        SerializeByteArray(buffer, baPseudoShell);
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

        mAuthDesKeyA    = DecodeJsonByteArray(jsonCardImage, "mAuthDesKeyA");
        mAuthDesKeyB    = DecodeJsonByteArray(jsonCardImage, "mAuthDesKeyB");
        mAuthPseudoKeyA = DecodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyA");
        mAuthPseudoKeyB = DecodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyB");
        baPseudoShell   = DecodeJsonByteArray(jsonCardImage, "baPseudoShell");
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
    //      Add the CM image to the JSON export.
    // ========================================
    protected void  JsonExport(JSONObject jsonCardImage) throws JSONException {                     // Add data to the JSON object.
        Log.d(TAG, "JsonExport");

        EncodeJsonByteArray(jsonCardImage, "mAuthDesKeyA",    mAuthDesKeyA);
        EncodeJsonByteArray(jsonCardImage, "mAuthDesKeyB",    mAuthDesKeyB);
        EncodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyA", mAuthPseudoKeyA);
        EncodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyB", mAuthPseudoKeyB);
        EncodeJsonByteArray(jsonCardImage, "baPseudoShell",   baPseudoShell);
        EncodeJsonByteArray(jsonCardImage, "baPseudoUID",     baPseudoUID);
        EncodeJsonByteArray(jsonCardImage, "baCapabillities", baCapabillities);
        EncodeJsonByteArray(jsonCardImage, "baAuthKasParams", baAuthKasParams);
        EncodeJsonByteArray(jsonCardImage, "baDir",           directory.Get());
        EncodeJsonByteArray(jsonCardImage, "baLog",           TTLog.baBody);
        JSONArray ipeList = new JSONArray();
        for (int i = 1; i < shell.getE(); i++) {
            if (!directory.E_Empty(i)) {                                                            // only occupied IPEs are exported
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

        Arrays.fill(baChallenge,     (byte)0);
        Arrays.fill(baChallengeTemp, (byte)0);
        sfAuthenticated       = sbool.False;
        sfPseudoAuthenticated = sbool.False;
        sfUsingPseudoShellUID = (baPseudoShell != null && baPseudoShell.length > 0) ? sbool.True : sbool.False;     // if we have a pseudo shell, we are "using it".
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
        sfAuthenticated       = sbool.invalid;                                                      //
        sfPseudoAuthenticated = sbool.invalid;                                                      //
    }

    // =============================================================================================    DeleteCheck (abstract implementation)
    // ========================================
    // DeleteCheck()
    //      may this card's image be deleted?
    //      An empty directory: yes.
    //      Any occupied IPE: ask the user.
    // ========================================
    public DeletePolicy DeleteCheck() {
        for (int i = 1; i < shell.getE(); i++) {                                                    // the IPE entries, as JsonExport walks them
            if (!directory.E_Empty(i)) {                                                            //      one is occupied
                return DeletePolicy.ASK;                                                            //      so let the user confirm
            }
        }
        return DeletePolicy.OK;                                                                     // nothing stored on the card
    }

    // =============================================================================================    Select (abstract implementation)
    // ========================================
    // Select()
    //      construct and return the FCI
    // ========================================
    public byte[] Select(byte[] baAid) throws VCardIntegrityException {                             // *** Card select
        Log.d(TAG, "Select");                                                                       //
        if      (sfUsingPseudoShellUID == sbool.True)  { return WrapAsFci(baAid, FciBuildRandom()); }   // Build FCI for random  UID host
        else if (sfUsingPseudoShellUID == sbool.False) { return WrapAsFci(baAid, FciBuildStatic()); }   //               static  UID host
        else {
            Log.e(TAG, "Select: Boolean is not TRUE or FALSE.");
            throw new VCardIntegrityException("Select: Boolean is not TRUE or FALSE.");
        }
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
        tagList.add(TlvBuild(bTagShell, baShell));
        tagList.add(TlvBuild(bTagCapabilities, baCapabillities));
        tagList.add(TlvBuild(bTagDirectory,    directory.Get()));
        tagList.add(TlvBuild(bTagOidList,      ConstructOids()));
        tagList.add(TlvBuild(bTagCss,          baCSS));
        tagList.add(TlvBuild(bTagChallenge,    ConstructChallenge(DesKeyA)));
        tagList.add(TlvBuild(bTagStaticUid, baUID));                                             // non standard...
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
        tagList.add(TlvBuild(bTagShell, baShell));
        tagList.add(TlvBuild(bTagDirectory,    directory.Get()));
        tagList.add(TlvBuild(bTagOidList,      ConstructOids()));
        tagList.add(TlvBuild(bTagChallenge,    ConstructChallenge(DesKeyA)));
        tagList.add(TlvBuild(bTagStaticUid, baUID));
        tagList.add(TlvBuild(bTagAuth,         baAuthKasParams));
        return TlvBuild((byte)0xA5, tagList);
    }



    private byte[] ConstructChallenge(SecretKey key) {                                              // *** ConstructChallenge
        Rng.nextBytes(baChallenge);                                                                 //  make random challenge

        if (shell.getKsc() == 0x04) {                                                               // ? DESFire style
            try {                                                                                   //
                Cip.init(Cipher.ENCRYPT_MODE, key, NullIV);                                         //      it needs to be encrypted
                baChallengeTemp = Cip.doFinal(baChallenge);                                         //
            } catch (Exception e) {                                                                 //
                Log.e(TAG, "ConstructChallenge: Encryption failed: " + e.getMessage());             //       report problems.
                System.arraycopy(baChallenge, 0, baChallengeTemp, 0, iCHALLENGE_SIZE);                   //
            }                                                                                       //
        }                                                                                           //
        else {                                                                                      // ? CMD2 style
            System.arraycopy(baChallenge, 0, baChallengeTemp, 0, iCHALLENGE_SIZE);                       //
        }                                                                                           //
                                                                                                    //
        return baChallengeTemp;                                                                     // That's all folks.
    }                                                                                               //

    private byte[] ConstructOids() {                                                                // *** ConstructOids
        byte[] baOids = new byte[2 * (shell.getE()-1)];                                             //      make a list of the IPE owners.
        for (int i = 1; i <= shell.getE()-1; i++) {                                                 //      One entry for each E/possible IPE (1..E-1)
            short sOid = 0;                                                                         //
            if (!directory.E_Empty(i)) {                                                            //      used?
                sOid = directory.E_Oid(i);                                                          //      get the OID (13 bits from directory.E[i])
                if (directory.E_Ext(i)) {                                                           //      Do we need to extend the OID by the ISAM fudge factor?
                    int iOff = 2 + (aIpe[i-1].baBody[0] & 0xFC);                                    //          Top bits are collected from the IPE's instance ID
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
    public static final int OurCLA           	=  0x90;

    public static final int INS_Authenticate  =  0x10;
    public static final int INS_ReadIpe       =  0x12;
    public static final int INS_ReadVrg       =  0x14;
    public static final int INS_ReadLog       =  0x16;
    public static final int INS_UpdateIpe     =  0x18;
    public static final int INS_UpdateVrg     =  0x1A;
    public static final int INS_UpdateLog     =  0x1C;
    public static final int INS_UpdateDir     =  0x1E;
    public static final int INS_EndSession    =  0x20;
    public static final int INS_Reselect      =  0x22;

    // ========================================
    // Dispatch()
    //      process the APDU
    //      return via
    // ========================================
    protected void Dispatch(Apdu apdu)  throws Apdu.ExitException  {                                 // *** Card dispatch
        Log.d(TAG, "Dispatch");

        boolean fAlreadyAuthenticated = (sfAuthenticated == sbool.True);                            // needs to be set before test's can report errors.

        try {
            if (apdu.apduCase == Apdu.ApduCase.Malformed) {                                         // have we been passed a good APDU?
                ApduException.Throw(Apdu.SW.UNKNOWN);                                               //      no, exit asap via the hash monitor
            }                                                                                       //

            if (apdu.Cla != OurCLA) {                                                               // Must be our CLA
                ApduException.Throw(Apdu.SW.CLA_NOT_SUPPORTED);                                     //      nothing else is good enough.
            }                                                                                       //

            if (sfAuthenticated == sbool.False) {                                                   // Not authenticated yet...
                switch (apdu.Ins) {                                                                 //      Which INS do we want ?
                    case INS_Authenticate:            DoAuthenticate(apdu);    break;               //      supported
                    case INS_ReadIpe:                 DoReadIpe(apdu);         break;               //      ..
                    case INS_ReadVrg:                 DoReadVrg(apdu);         break;               //      ..
                    case INS_ReadLog:                 DoReadLog(apdu);         break;               //      ..
                    case INS_Reselect:                DoReselect(apdu);        break;               //      ..
                    case INS_UpdateIpe:                                                             //      unsupported
                    case INS_UpdateVrg:                                                             //      ..
                    case INS_UpdateLog:                                                             //      ..
                    case INS_UpdateDir:                                                             //      ..
                    case INS_EndSession:                                                            //      ..
                        ApduException.Throw(Apdu.SW.SECURITY_STATUS_NOT_SATISFIED);                 //
                    default:                                                                        //      all others
                        ApduException.Throw(Apdu.SW.INS_NOT_SUPPORTED);                             //          unrecognised
                }                                                                                   //
            }                                                                                       //
            else if (sfAuthenticated == sbool.True) {                                               // Authenticated, so Secure session active
                switch (apdu.Ins) {                                                                 //      Which INS do we want ?
                    case INS_ReadIpe:                 DoReadIpe(apdu);        break;                //      supported
                    case INS_ReadVrg:                 DoReadVrg(apdu);        break;                //      ..
                    case INS_ReadLog:                 DoReadLog(apdu);        break;                //      ..
                    case INS_UpdateIpe:               DoUpdateIpe(apdu);      break;                //      ..
                    case INS_UpdateVrg:               DoUpdateVrg(apdu);      break;                //      ..
                    case INS_UpdateLog:               DoUpdateLog(apdu);      break;                //      ..
                    case INS_UpdateDir:               DoUpdateDir(apdu);      break;                //      ..
                    case INS_EndSession:              DoEndSession(apdu);     break;                //      ..
                    case INS_Authenticate:                                                          //      not once fully authenticated
                    case INS_Reselect:                                                              //      ..
                        ApduException.Throw(Apdu.SW.SECURITY_STATUS_NOT_SATISFIED);                 //
                    default:                                                                        //      all others
                        ApduException.Throw(Apdu.SW.INS_NOT_SUPPORTED);                             //          unrecognised
                }                                                                                   //
            } else {                                                                                // not true or false == trouble.
                Log.e(TAG, "Dispatch: Boolean is not TRUE or FALSE.");
                throw new VCardIntegrityException("Dispatch: Boolean is not TRUE or FALSE.");
            }
        }
        catch (Apdu.ExitException e) {                                                              // All handler responses caught here
            if (fAlreadyAuthenticated && (sfAuthenticated == sbool.True)) {                         // if we were, and still are, authenticated.
                Hash.update(apdu.baApdu);                                                           // then, this exchange should be hashed.
                Hash.update(e.GetResponse());                                                       //       Tx data including non-9000 SWs.
            }                                                                                       //
            throw e;                                                                                // rethrow so that VCard can deliver the reply.
        }
        catch (Exception e) {                                                                       // All others caught here
            Log.d(TAG, "Dispatch: " + e.getMessage());
            ApduException.Throw(Apdu.SW.UNKNOWN);
        }
    }


    // ##########################################################################
    // #  Function: DoAuthenticate
    // #        Authenticate APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoAuthenticate(Apdu apdu) throws Apdu.ExitException, VCardIntegrityException {     // *** DoAuthenticate
        // ToDo: test for case ?

        if (sfAuthenticated == sbool.True) {   		     					                        // Should not be permitted if we are already authenticated.
            ApduException.Throw(Apdu.SW.SECURITY_STATUS_NOT_SATISFIED);		         		     	//      Not happy response
        }																							//
        else if (sfAuthenticated != sbool.False) {                                                  //
            Log.e(TAG, "DoAuthenticate: Boolean is not TRUE or FALSE.");
            throw new VCardIntegrityException("DoAuthenticate: Boolean is not TRUE or FALSE.");
        }

        if ((apdu.P1 != 0) || (apdu.P2 != 0)) {                                                     // P1 & P2 must be zero
            ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                            //      Oops. it's not
        }                                                                                           //

        if ((apdu.apduCase != Apdu.ApduCase.Four) ||
            (apdu.Lc != 16) ||                                                                      // Auth expects 16 in
            ((apdu.Le != 8) && (!apdu.fAsMuchAsWeHave))) {                                          // and 8 out (Le=0 is forgiven)
                ApduException.Throw(Apdu.SW.WRONG_LENGTH);						    				//      Not happy response
        }																							//

        byte[] baResponse;                                                                          // response to the challenge's response.
        try {
            try {
                if      (shell.getKsc() == 0x03) { baResponse = DoAuthenticateKsc03(apdu); }        // CMD2 style authenticate. (Exception on failure)
                else if (shell.getKsc() == 0x04) { baResponse = DoAuthenticateKsc04(apdu); }        // Desfire style authentication
                else {                                                                              // Anything else is problematic.
                    Log.e(TAG, "DoAuthenticate: KSC is not 0x03 or 0x04.");                         //
                    throw new VCardIntegrityException("DoAuthenticate: KSC is not 0x03 or 0x04.");  //
                }                                                                                   //
                ApduException.Throw(baResponse, Apdu.SW.NO_ERROR);									// Exit Happy.
            }
            catch (AuthenticationException e) {                                                     // Session key crypto failures end here.
                ApduException.Throw(Apdu.SW.SECURITY_STATUS_NOT_SATISFIED);                         //      Not happy response
            }                                                                                       //
            catch (Apdu.ExitException e) {                                                          // SW error responses will be rethrown
                throw e;                                                                            //
            }                                                                                       //
            catch (Exception e) {                                                                   // All other exceptions end here.
                Log.d(TAG, "DoAuthenticate: " + e.getMessage());                                    //       Leave a clue about what went wrong!
                ApduException.Throw(Apdu.SW.UNKNOWN);                                               //
            }
        }
        finally {                                                                                   // A challenge may be answered only once, right or wrong:
            Rng.nextBytes(baChallenge);                                                             //      replace it with one nobody has seen,
            Arrays.fill(baChallengeTemp, (byte)0);                                                  //      so retries and replays need a new Select/Reselect.
        }
    }

    private byte[] DoAuthenticateKsc03(Apdu apdu) throws Apdu.ExitException,
                                                         VCardIntegrityException,
                                                         AuthenticationException {                  // *** DoAuthenticate CMD2 style
        byte[] baResponse = null;
        if (sfUsingPseudoShellUID == sbool.True) {                                                  // PseudoShell used
            if (sfPseudoAuthenticated == sbool.False) {                                             //      and not yet authenticated
                baResponse = GenSessionKey_Cmd2Style(apdu, DesKeyPseudoA, DesKeyPseudoB);           //          Authenticate (Exception on failure)
                sfPseudoAuthenticated = sbool.True;                                                 //          OK
            }
            else if (sfPseudoAuthenticated == sbool.True) {                                         //      and already authenticated
                baResponse = GenSessionKey_Cmd2Style(apdu, DesKeyA, DesKeyB);                       //          Authenticate (Exception on failure)
                sfAuthenticated = sbool.True;                                                       //          Auth state.
                Hash.reset();                                                                       //          initialise Apdu Hash
            }                                                                                       //
            else {                                                                                  //      anything else is a problem
                Log.e(TAG, "DoAuthenticate: Boolean is not TRUE or FALSE.");                        //
                throw new VCardIntegrityException("DoAuthenticate: Boolean is not TRUE or FALSE.");
            }
        }
        else if (sfUsingPseudoShellUID == sbool.False) {                                            // Normal shell being used
            baResponse = GenSessionKey_Cmd2Style(apdu, DesKeyA, DesKeyB);                           //      Authenticate (Exception on failure)
            sfAuthenticated = sbool.True;                                                           //      Auth state.
            Hash.reset();                                                                           //      initialise Apdu Hash
        }
        else {                                                                                      // undetermined shell being used
            Log.e(TAG, "DoAuthenticate: Boolean is not TRUE or FALSE.");                            //      Not happy about this!
            throw new VCardIntegrityException("DoAuthenticate: Boolean is not TRUE or FALSE.");     //
        }                                                                                           //
        return baResponse;                                                                          // We have data. return it
    }

    private byte[] DoAuthenticateKsc04(Apdu apdu) throws Apdu.ExitException,
                                                         VCardIntegrityException,
                                                         AuthenticationException {                  // *** DoAuthenticate CMD7 style
        byte[] baResponse = null;
        if (sfUsingPseudoShellUID == sbool.True) {                                                  // PseudoShell used
            if (sfPseudoAuthenticated == sbool.False) {                                             //      and not yet authenticated
                baResponse = GenSessionKey_Cmd7Style(apdu, DesKeyPseudoA);                          //          Authenticate (Exception on failure)
                sfPseudoAuthenticated = sbool.True;                                                 //          PseudoAuth state.
            }
            else if (sfPseudoAuthenticated == sbool.True) {                                         //      and already authenticated
                baResponse = GenSessionKey_Cmd7Style(apdu, DesKeyA);                                //          Authenticate (Exception on failure)
                sfAuthenticated = sbool.True;                                                       //          Auth state.
                Hash.reset();                                                                       //          initialise Apdu Hash
            }                                                                                       //
            else {                                                                                  //      anything else is a problem
                Log.e(TAG, "DoAuthenticate: Boolean is not TRUE or FALSE.");                        //
                throw new VCardIntegrityException("DoAuthenticate: Boolean is not TRUE or FALSE."); //
            }
        }
        else if (sfUsingPseudoShellUID == sbool.False) {                                            // Normal shell being used
            baResponse = GenSessionKey_Cmd7Style(apdu, DesKeyA);                                    //      Authenticate (Exception on failure)
            sfAuthenticated = sbool.True;                                                           //      Auth state.
            Hash.reset();                                                                           //      initialise Apdu Hash
        }
        else {                                                                                      // undetermined shell being used
            Log.e(TAG, "DoAuthenticate: Boolean is not TRUE or FALSE.");                            //      Not happy about this!
            throw new VCardIntegrityException("DoAuthenticate: Boolean is not TRUE or FALSE.");     //
        }                                                                                           //
        return baResponse;                                                                          // We have data. return it
    }


    private	byte[] GenSessionKey_Cmd2Style(Apdu apdu, SecretKey KeyA, SecretKey KeyB) 	                        // Verify PCD's response to our challenge
                                                                   throws AuthenticationException {             //      and generate our Response to their challenge
        try {                                                                                                   //
            Cip.init(Cipher.ENCRYPT_MODE, KeyA, NullIV);                                                        // Encrypt our challenge data
            byte[] baChallengeTemp = Cip.doFinal(baChallenge);                                                  //
                                                                                                                //
            if ( ! BytesMatch(apdu.baRxData, 0, baChallengeTemp, 0, iCHALLENGE_SIZE)) {                         // Compare with offered data (time invariance does not matter, its RND and unrepeatable)
                throw new AuthenticationException();                                                            // 		Exit Mr Grumpy.
            }                                                                                                   //
                                                                                                                //
            // Note: We only encrypt their data if they got ours right!											//
            Cip.init(Cipher.ENCRYPT_MODE, KeyB, NullIV);                                                        // POST's challenge
            byte[] baResponse = Cip.doFinal(apdu.baRxData, iCHALLENGE_SIZE, iCHALLENGE_SIZE);                   // Calculate our reply @0 <= Response data to caller
                                                                                                                //
            byte[] baSessionSeed = new byte[16];                                                                // Build the session key seed data
            System.arraycopy(baChallenge,        4, baSessionSeed,  0, 4);                                      //      c4c5c6c7
            System.arraycopy(apdu.baRxData,     12, baSessionSeed,  4, 4);                                      //              r1r2r3r4
            System.arraycopy(baChallenge,        0, baSessionSeed,  8, 4);                                      //                      c1c2c3c4
            System.arraycopy(apdu.baRxData,      8, baSessionSeed, 12, 4);                                      //                              r4r5r6r7
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

    private	byte[] GenSessionKey_Cmd7Style(Apdu apdu, SecretKey Key) throws AuthenticationException {           // Verify PCD's response to our challenge
                                                                                                                //      and generate our Response to their challenge
        try {                                                                                                   //
            short sByteCount = (short)0;
            Cip.init(Cipher.ENCRYPT_MODE, Key, NullIV);
            byte[] baRndA = Cip.doFinal(apdu.baRxData, 0, iCHALLENGE_SIZE);                                     // encrypt the PCD's response. Expecting [RndA :: Rot(RndB)]

            Cip.init(Cipher.ENCRYPT_MODE, Key, NullIV);
            byte[] baRotRnd = Cip.doFinal(apdu.baRxData, 8, iCHALLENGE_SIZE);

            for (int i = 0; i < iCHALLENGE_SIZE; i++) {                                                         // DESFires CBC is weird.
                baRotRnd[i] ^= apdu.baRxData[i];                                                                //
            }                                                                                                   //

            if ((! BytesMatch(baRotRnd, 0, baChallenge, 1, iCHALLENGE_SIZE -1)) ||                              // Expecting RndB rotated left one byte: b1..b7
                (! BytesMatch(baRotRnd, iCHALLENGE_SIZE -1, baChallenge, 0, 1))) {                              //                                         b0. All 8 must match.
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
            return Cip.doFinal(baRotRnd, 0, iCHALLENGE_SIZE);                                                        // Response = encrypted PCD's rotated RndA

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
    private void DoReadIpe(Apdu apdu) throws Apdu.ExitException, VCardIntegrityException {       // *** DoReadIpe
        // ToDo: test for case ?

        int iIpeNo = apdu.P1;

        if ((apdu.apduCase != Apdu.ApduCase.Two) || (!apdu.fAsMuchAsWeHave)) {                      // we want case 2 read all.
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);			                                    //
        }																                            //

        if ((iIpeNo == 0) ||                                                                        // Check != 0
            (iIpeNo > (shell.getE()-1)) ||                                                          //       <= E-1
            (apdu.P2 != 0)) {                                                                       //       P2 as prescribed, zero.
                ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                        //      Oops. it's not
        }                                                                                           //

        if (directory.E_Empty(iIpeNo)) {                                                            // Confirm the IPE is not empty
            ApduException.Throw(Apdu.SW.RECORD_NOT_FOUND);                                          // Report "Record Not Found" as per spec.
        }

        int iIpeSize         = (aIpe[iIpeNo-1].baBody[0] & 0xfC);                                   // Size of IPE body + InstanceID + seal.
        byte[] baDeliverable = new byte[5 + iIpeSize + 16];                                         // Get the IPE

        System.arraycopy(directory.getEntry(iIpeNo), 0, baDeliverable, 0, 5);                       // Dir entry +
        if (sfAuthenticated == sbool.True) {                                                        // Auth : Body + seal
            System.arraycopy(aIpe[iIpeNo - 1].baBody, 0, baDeliverable, 5, iIpeSize+16);
        }
        else if  (sfAuthenticated == sbool.False) {
            System.arraycopy(aIpe[iIpeNo - 1].baBody, 0, baDeliverable, 5, iIpeSize);               //      : Body +
            Arrays.fill(baDeliverable, 5 + iIpeSize, 5 + iIpeSize + 16, (byte) 0xff);               //      :        redacted
        }
        else {
            Log.e(TAG, "DoReadIpe: Boolean is not TRUE or FALSE.");
            throw new VCardIntegrityException("DoReadIpe: Boolean is not TRUE or FALSE.");
        }

        ApduException.Throw(baDeliverable, Apdu.SW.NO_ERROR);
    }


    // ##########################################################################
    // #  Function: DoReadVrg
    // #        Read VRG  APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoReadVrg(Apdu apdu) throws Apdu.ExitException, VCardIntegrityException {           // *** DoReadVrg
        // ToDo: test for case ?

        int iIpeNo = apdu.P1;

        if ((apdu.apduCase != Apdu.ApduCase.Two) || (!apdu.fAsMuchAsWeHave)) {                      // we want case 2 read all.
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);			                                    //
        }																                            //

        if ((iIpeNo == 0) ||                                                                        // Check != 0
            (iIpeNo > (shell.getE()-1)) ||                                                          //       <= E-1
            (apdu.P2 != 0)) {                                                                       //       P2 as prescribed, zero.
                ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                        //      Oops. it's not
        }                                                                                           //

        if (directory.E_Empty(iIpeNo)) {                                                            // Confirm the IPE is not empty
            ApduException.Throw(Apdu.SW.RECORD_NOT_FOUND);                                          // Report "Record Not Found" as per spec.
        }

        int iVrgSize         = (aVrg[iIpeNo-1].baBody[0] & 0xfC);                                   // Size of VRG body + InstanceID + seal.
        byte[] baDeliverable = new byte[5 + iVrgSize + 16];                                         // Get the VRG

        System.arraycopy(directory.getEntry(iIpeNo), 0, baDeliverable, 0, 5);                       // Dir entry +
        if (sfAuthenticated == sbool.True) {
            System.arraycopy(aVrg[iIpeNo - 1].baBody, 0, baDeliverable, 5, iVrgSize+16);            // Auth : Body + seal
        }
        else if (sfAuthenticated == sbool.False) {
            System.arraycopy(aVrg[iIpeNo - 1].baBody, 0, baDeliverable, 5, iVrgSize);               //      : Body +
            Arrays.fill(baDeliverable, 5 + iVrgSize, 5 + iVrgSize + 16, (byte) 0xff);               //      :        redacted
        }
        else {
            Log.e(TAG, "DoReadVrg: Boolean is not TRUE or FALSE.");
            throw new VCardIntegrityException("DoReadVrg: Boolean is not TRUE or FALSE.");
        }

        ApduException.Throw(baDeliverable, Apdu.SW.NO_ERROR);
    }

    // ##########################################################################
    // #  Function: DoReadLog
    // #        Read TT-Log APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoReadLog(Apdu apdu) throws Apdu.ExitException, VCardIntegrityException {           // *** DoReadLog
        // ToDo: test for case ?

        if ((apdu.apduCase != Apdu.ApduCase.Two) || (!apdu.fAsMuchAsWeHave)) {                      // we want case 2 read all.
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);			                                    //
        }																                            //

        if ((apdu.P1 < 1) || (apdu.P1 > 5)	||                                                      // record count, 1..5 == OK
            (apdu.P2 != 0)) {							                                            //     P2 must be zero
                ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                        //  Go home if we don't like it.
        }

        short  sLen          = (short)(apdu.P1 * 0x30);                                             // how many * record size
        byte[] baDeliverable = new byte[sLen];                                                      // Space needed

        System.arraycopy(TTLog.baBody, 0, baDeliverable, 0, sLen);                                  // Records copied

        ApduException.Throw(baDeliverable, Apdu.SW.NO_ERROR);
    }

    // ##########################################################################
    // #  Function: DoReselect
    // #        Reselection  APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoReselect(Apdu apdu) throws Apdu.ExitException, VCardIntegrityException {      // *** DoReselect
        byte[] baA5Material;

        if ((apdu.apduCase != Apdu.ApduCase.Two) || (!apdu.fAsMuchAsWeHave)) {                      // we want case 2 read all.
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);			                                    //
        }																                            //

        if ((apdu.P1 != 0) || (apdu.P2 != 0)) {                                                     // P1 & P2 must be zero
            ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                            //      Oops. it's not
        }                                                                                           //

        if (sfUsingPseudoShellUID == sbool.True) {                                                  // if pseudo shell ...
            if      (sfPseudoAuthenticated == sbool.False) { baA5Material = FciBuildRandom(); }     //                 and not pseudo authenticated, reissue the Random UID FCI
            else if (sfPseudoAuthenticated == sbool.True)  { baA5Material = FciBuildReselect(); }   //                 and pseudo authenticated, reissue the Reselect FCI
            else {                                                                                  //                 otherwise we are in trouble!
                Log.e(TAG, "DoReselect: Boolean is not TRUE or FALSE.");
                throw new VCardIntegrityException("DoReselect: Boolean is not TRUE or FALSE.");
            }
        }
        else if (sfUsingPseudoShellUID == sbool.False) {                                            // if normal shell, just issue the Reselect FCI
            baA5Material = FciBuildReselect();                                                      //
        }                                                                                           //
        else {                                                                                      // not pseudo & not normal ...
            Log.e(TAG, "DoReselect: Boolean is not TRUE or FALSE.");                                //    seriously unhappy
            throw new VCardIntegrityException("DoReselect: Boolean is not TRUE or FALSE.");         //
        }                                                                                           //

        ApduException.Throw( WrapAsFci(null, baA5Material), Apdu.SW.NO_ERROR);                      // FCI build without the application AID.
    }


    // ##########################################################################
    // #  Function: DoUpdateIpe
    // #        IPE write APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoUpdateIpe(Apdu apdu) throws Apdu.ExitException {                              // *** DoUpdateIpe

        // ToDo: test for case 3

        int iIpeNo   = apdu.P1-1;                                                                   // IPE[1..E-1] ==> range 0..E-2
        int iDataLen = apdu.Lc;                                                                     // Payload size
        UpdateCheckIpeNo(apdu, iIpeNo);                                                             // IPE# happy?
        UpdateCheckLength(apdu, iDataLen);                                                          // Len happy ?
        UpdateCheckPassword(apdu, iIpeNo);                                                          // Password Happy ?
        UpdateStoreAndExit(apdu, aIpe[iIpeNo].baBody, iDataLen);                                    // Copy new data to page and update the hash exit Happy exception.
    }

    private void UpdateCheckIpeNo(Apdu apdu, int  iIpeNo) throws Apdu.ExitException {               // check parameters and collect data
        if ((iIpeNo < 0) || ((shell.getE()-2) < iIpeNo) || (apdu.P2 != 0)) {                        // Check IPE(1..E-1) & P2==0 before continuing
            ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                            //      Oops. it's not
        }                                                                                           //
    }                                                                                               //

    private void UpdateCheckLength(Apdu apdu, int iLen) throws Apdu.ExitException {                 // check parameters and collect data
        if ((apdu.apduCase != Apdu.ApduCase.Three) ||                                               // we want case 3 write with no read
            (apdu.Lc <= iPASSWORD_SIZE) ||                                                          // should be big enough to hold length at least
            (iLen != (iPASSWORD_SIZE +(apdu.baRxData[iPASSWORD_SIZE] & 0xFC) + 16)) ||              // length should be pwd::ipe::seal
            ((apdu.baRxData[iPASSWORD_SIZE] & 0xFC) > iIPE_MAXSIZE) ) {                             // and <= limit to fit in an APDU
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);											    //
        }                                                                                           //
    }                                                                                               //

    private void UpdateCheckPassword(Apdu apdu, int iSlot) throws Apdu.ExitException {	            // check parameters and collect data
        byte[] baTmp = Arrays.copyOfRange(apdu.baRxData, 0, iPASSWORD_SIZE);                        // Just the pwd bit
        if (! MessageDigest.isEqual(baTmp, aPassword[iSlot].baBody)) {                              // ** Time invariant **  check of the password.
            ApduException.Throw(Apdu.SW.AUTHENTICATION_FAILURE);                                    //      Fail. Bad luck!
        }                                                                                           //
    }                                                                                               //

    private void UpdateStoreAndExit(Apdu apdu, byte[] baPage, int iLen) throws Apdu.ExitException {
        System.arraycopy(apdu.baRxData, iPASSWORD_SIZE,                                             // source,          // Copy new contents to the page
                         baPage, 0,                                                                 // destination      //
                         iLen - iPASSWORD_SIZE);                                                    // size.            //
        ApduException.Throw(Apdu.SW.NO_ERROR);                                                      // Happy ending.
    }

    // ##########################################################################
    // #  Function: DoUpdateVrg
    // #        VRG Write APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoUpdateVrg(Apdu apdu) throws Apdu.ExitException {                                 // *** DoUpdateVrg
        // ToDo: test for case 3

        int iIpeNo   = apdu.P1 - 1;                                                                 // IPE[1..E-1] ==> range 0..E-2
        int iDataLen = apdu.Lc;                                                                     // Payload size
        UpdateCheckIpeNo(apdu, iIpeNo);                                                             // IPE# happy?
        UpdateCheckLength(apdu, iDataLen);                                                          // Len happy ?
        UpdateCheckPassword(apdu, iIpeNo);                                                          // Password Happy ?
        UpdateStoreAndExit(apdu, aVrg[iIpeNo].baBody, iDataLen);                                    // Copy new data to page and update the hash exit Happy exception.
    }


    // ##########################################################################
    // #  Function: DoUpdateLog
    // #        TT-Log Write APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoUpdateLog(Apdu apdu) throws Apdu.ExitException, Exception {                      // *** DoUpdateLog
        // ToDo: test for case 3

        if (apdu.apduCase != Apdu.ApduCase.Three)  {                                                // we want case 3 write with no read
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);                                              //      Oops. it's not what we prescribed
        }                                                                                           //

        if ((apdu.P1 != 0) || (apdu.P2 != 0)) {                                                     // P1 & P2 must be zero
            ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                            //      Oops. it's not
        }                                                                                           //

        int iIpeNo   = shell.getE() -1;                                                             // IPE # E is reserved for the log
        int iDataLen = apdu.Lc;                                                                     // Payload size
        if ((iDataLen < iPASSWORD_SIZE + 1) || (iPASSWORD_SIZE + 0x30 < iDataLen)) {                // length should be pwd::logRecord[1..30]
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);                                              //      Oops. it's not
        }                                                                                           //
        UpdateCheckPassword(apdu, iIpeNo);                                                          // Password Happy ?
        System.arraycopy(TTLog.baBody, 0, TTLog.baBody, 0x30, TTLog.baBody.length - 0x30);          // Shuffle old records 0..4 to new 1..5
        Arrays.fill(TTLog.baBody, 0, 0x30, (byte) 0);                                               // Clear record #0 so a short record is padded with zeros
        UpdateStoreAndExit(apdu, TTLog.baBody, iDataLen);                                           // Squeeze in the new record at #0 &  hash exit Happy exception.
    }

    // ToDo: test when the body < password length

    // ##########################################################################
    // #  Function: DoUpdateDir
    // #        Directory Write APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns:
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoUpdateDir(Apdu apdu) throws Apdu.ExitException, Exception {                      // *** DoUpdateDir
        // ToDo: test for case 3
        // ToDo: as per log above. See common code.
        if (apdu.apduCase != Apdu.ApduCase.Three)  {                                                // we want case 3 write with no read
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);                                              //      Oops. it's not what we prescribed
        }                                                                                           //

        if ((apdu.P1 != 0) || (apdu.P2 != 0)) {                                                     // P1 & P2 must be zero
            ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                            //      Oops. it's not
        }                                                                                           //

        int iIpeNo   = shell.getE();                                                                // IPE # E+1 is reserved for the Directory
        int iDataLen = apdu.Lc;                                                                     // Payload size
        if (iDataLen != iPASSWORD_SIZE + directory.getLength()) {                                   // length should be pwd::logRecord[30]
            ApduException.Throw(Apdu.SW.WRONG_LENGTH);                                              //      Oops. it's not
        }                                                                                           //

        UpdateCheckPassword(apdu, iIpeNo);                                                          // Password Happy ?
        directory.Update(apdu.baRxData, iPASSWORD_SIZE);                                            //
        ApduException.Throw(Apdu.SW.NO_ERROR);                                                      // Happy ending.
    }


    // ##########################################################################
    // #  Function: DoEndSession
    // #        Commit changes and session end APDU manager.
    // #
    // #  Parameters:
    // #        Apdu apdu - The APDU sent by the PCD.
    // #
    // #  Returns by ApduExitException
    // #        byte[] - This ICC's response including the Status word.
    // #
    // #  See Also:
    // #
    // ##########################################################################
    private void DoEndSession(Apdu apdu) throws Apdu.ExitException, Exception {                     // *** DoEndSession
        // ToDo: test for case 4

        sfAuthenticated = sbool.False;                                                              // Always terminate the SM now this has been called.

        byte[] baSig;
        try {                                                                                       // Any failure from here on ends the session uncommitted,
            if ((apdu.apduCase != Apdu.ApduCase.Four) || (apdu.Lc != iCSS_SIZE)) {                  // we want case 4 && Check Len = sig size.
                ApduException.Throw(Apdu.SW.WRONG_LENGTH);                                          //
            }                                                                                       //

            if ((apdu.P1 != 0) || (apdu.P2 != 0)) {                                                 //  P1 & P2 should = 0
                ApduException.Throw(Apdu.SW.INCORRECT_P1P2);                                        //
            }
            if (apdu.Lc != iCSS_SIZE) {                                                             // Check Len = sig size.
                ApduException.Throw(Apdu.SW.WRONG_LENGTH);                                          //
            }                                                                                       //

            byte[] baMac = Hash.digest();                                                           // This is our Hash of the earlier APDUs

            if ((baMac.length % 8) != 0) {                                                          // Padded if the MAC is not block of 8
                baMac = Arrays.copyOfRange(baMac, 0, ((baMac.length + 7) / 8) * 8);                 //
            }                                                                                       //

            Sig.init(Cipher.ENCRYPT_MODE, SessionKey, new IvParameterSpec(new byte[8]));            // We do Sig as a DES MAC
            baSig = Sig.doFinal(baMac);                                                             // Calculate the MAC. it's the last block here
            if (!BytesMatch(apdu.baRxData, 0, baSig, baSig.length - 8, 8)) {                        // Check we agree with the caller.
                ApduException.Throw(Apdu.SW.AUTHENTICATION_FAILURE);                                //      Not happy!
            }                                                                                       //
        }
        catch (Exception e) {                                                                       // ... so drop all the session's changes
            ImageReload();                                                                          //      reload the committed image
            throw e;                                                                                //      and report the failure.
        }

        Sig.init(Cipher.ENCRYPT_MODE, SessionKey, new IvParameterSpec(new byte[8]));                //
        baCSS = Sig.doFinal(baSig, baSig.length - iCSS_SIZE, iCSS_SIZE);                            // CSS response = enc(TS)
        incTsn();																	                // Transaction number ++
        ImageSave();
        ApduException.Throw(baCSS, Apdu.SW.NO_ERROR);
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
        if (baV.length == iSECTOR_SIZE) return baV;
        else return Arrays.copyOf(baV, iSECTOR_SIZE);
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