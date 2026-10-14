package com.digitallocksmiths.ItsoHce.VcardCmd11;

// ToDo: Consider this strategy....
//       Select: Copy NVM sectors to RAM.
//       Process: Work directly on RAM copies.
//       EndSession: If verified, copy RAM to NVM.

//          Sectors in an encrypted file where TSN (or SCC) is the IV.
//          Passwords encrypted with NULL IV.
//          MMMTs no longer need 'sector and spare' tables.
//          MMMTs signed with CSS diversified key
//
//          MMMT A & B have separate dynamic keys. In keyStore and changing on each save.
//          If the MMMT is replayed it will fail to decrypt. While A/B rollback still works
//          If the sector data is replayed the decrypt will fail. due to IV changes.
//
//          Or
// combine sectors and MMMT is a mega structure.
// Keep version A/B encrypted with Keys A/B
// Key changes on every save.
//


import static java.lang.Math.min;

import android.util.Base64;
import android.util.Log;

import com.digitallocksmiths.ItsoHce.VCard;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.Arrays;


public class Cmd11 extends VCard {
    private static final String TAG = "Cmd11";

    private static final byte  bCHAL_SIZE       =   8;                                              // Size of Random Challenge Data
    private static final short sPAGE_SIZE       = 256;                                              // size of sector (IPE or VRG records)
    private static final byte  bPWD_SIZE        =   8;
    private static final short sFREE_PAGE_COUNT =   8;

    private static class Sector   { byte[] baBody = new byte[sPAGE_SIZE]; }
    private static class Password { byte[] baBody = new byte[bPWD_SIZE];  }

    // ==========================================================================
    // Clear on reset 'RAM' variables

    public byte[]  baChallenge          = new byte[bCHAL_SIZE];
    public byte[]  baChallengeTemp      = new byte[bCHAL_SIZE];
    public boolean fAuthenticated       = false;                                                    // Bool vars
    public boolean fPseudoAuthenticated = false;
    public short   sFciStart            = 0;                                                        // Short vars
    public short   sFciA5LenOffset      = 0;
    public short   sAllocated           = 0;
    public Mmmt    hLatest              = null;                                                     // Object vars
    public Mmmt    hOldest              = null;

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
    private byte[] baAuthKasParams;

    private final Mmmt  MmmtA = new Mmmt(nvm, "MmmtA", "MmmtB");
    private final Mmmt  MmmtB = new Mmmt(nvm, "MmmtB", "MmmtA");

    private Sector[]    aSector   = null;                                                           // Ipes + Vrgs log & Dir + workspece       [2 + Shell.E-1 + sFREE_PAGE_COUNT]
    private Password[]  aPassword = null;                                                           // Passwords  [ditto]

//  public static RandomData    Rng;                                                                // Shared Random generator.
//  public static Checksum      Crc;                                                                //        CRC resource.
//  public static Cipher        Cip;                                                                // 		  challenge processor/SK generator.
//  public static Signature     Sig;                                                                // 		  MAC verifyer/generator.
//  public static DESKey        SessionKey;                                                         //        ephemeral (transient) session key.
//  public static MessageDigest Hash;                                                               //		  Apdu Message disest.



    // ========================================
    // Constructor
    //
    // ========================================
    public Cmd11()  throws VCard.VirtualCardException {
        super();
        TitleSet("Uninitialized CMD 11 Card Image");
    }

    // ========================================
    // ImageGetSize()
    //    Return the size of the serialized image in bytes.
    // ========================================
    public int      ImageGetSize() {                                                                // subclasses indicate their own storage volume requirements
        Log.d(TAG, "ImageGetSize");
        // ToDo: Deserialize the image here.
        return  SerializeOverhead + baAid.length +
                SerializeOverhead + mAuthDesKeyA.length +
                SerializeOverhead + mAuthDesKeyB.length +
                SerializeOverhead + mAuthPseudoKeyA.length +
                SerializeOverhead + mAuthPseudoKeyB.length +
                SerializeOverhead + baPseudoShell.length +
                SerializeOverhead + baUID.length +
                SerializeOverhead + baPseudoUID.length +
                SerializeOverhead + baAuthKasParams.length;
                //MmmtA
                //MmmtB
                //aSector
                //aPassword
    };

    // ========================================
    // ImageDeserialize()
    //      Make a new VCard from NVM store.
    // ========================================
    public void     ImageDeserialize(ByteBuffer buffer) {                                           // subclasses populate their working variables here.
        Log.d(TAG, "ImageDeserialize");
        // ToDo: Deserialize the image here.
        baAid           = DeserializeByteArray(buffer);
        mAuthDesKeyA    = DeserializeByteArray(buffer);
        mAuthDesKeyB    = DeserializeByteArray(buffer);
        mAuthPseudoKeyA = DeserializeByteArray(buffer);
        mAuthPseudoKeyB = DeserializeByteArray(buffer);
        baPseudoShell   = DeserializeByteArray(buffer);
        baUID           = DeserializeByteArray(buffer);
        baPseudoUID     = DeserializeByteArray(buffer);
        baAuthKasParams = DeserializeByteArray(buffer);
        //MmmtA
        //MmmtB
        //aSector
        //aPassword
    }

    // ========================================
    // ImageSerialize()
    //      Add this class's image variables
    //      to the buffer.
    // ========================================
    public void     ImageSerialize(ByteBuffer buffer) {                                             // subclasses serialize their variables here.
        Log.d(TAG, "ImageSerialize");
        // ToDo: Serialize the image here.
        SerializeByteArray(buffer, baAid);
        SerializeByteArray(buffer, mAuthDesKeyA);
        SerializeByteArray(buffer, mAuthDesKeyB);
        SerializeByteArray(buffer, mAuthPseudoKeyA);
        SerializeByteArray(buffer, mAuthPseudoKeyB);
        SerializeByteArray(buffer, baPseudoShell);
        SerializeByteArray(buffer, baUID);
        SerializeByteArray(buffer, baPseudoUID);
        SerializeByteArray(buffer, baAuthKasParams);
        //MmmtA
        //MmmtB
        //aSector
        //aPassword
    }




    // ========================================
    // JsonParse(JSONObject szJsonCardImage)
    //      Make a new VCard from the JSON image.
    // ========================================
    public void JsonParse(JSONObject szJsonCardImage) throws JSONException, VirtualCardException {  // parse the JSON image into the CM Image
        Log.d(TAG, "JsonParse");
        // ToDo: Test this
        //do it ASAP

        // shell was read and parsed by the caller.

        baAid           = DecodeJsonByteArray(szJsonCardImage, "baAid");
        mAuthDesKeyA    = DecodeJsonByteArray(szJsonCardImage, "mAuthDesKeyA");
        mAuthDesKeyB    = DecodeJsonByteArray(szJsonCardImage, "mAuthDesKeyB");
        mAuthPseudoKeyA = DecodeJsonByteArray(szJsonCardImage, "mAuthPseudoKeyA");
        mAuthPseudoKeyB = DecodeJsonByteArray(szJsonCardImage, "mAuthPseudoKeyB");
        baPseudoShell   = DecodeJsonByteArray(szJsonCardImage, "baPseudoShell");
        baUID           = DecodeJsonByteArray(szJsonCardImage, "baUID");
        baPseudoUID     = DecodeJsonByteArray(szJsonCardImage, "baPseudoUID");
        baAuthKasParams = DecodeJsonByteArray(szJsonCardImage, "baAuthKasParams");

        MmmtA.Erase();                                                                              // Erase old data from the NVM Back-up copies (currently in RAM!)
        MmmtB.Erase();                                                                              //
        hLatest  = MmmtA;                                                                           //
        hOldest  = MmmtB;                                                                           //

        aSector   = new Sector[2*(shell.getE() - 1) + 2  + sFREE_PAGE_COUNT];                       // Sectors Ipe[E-1 sectors] Vrg[E-1 sectors] + log + dir + free count
        for (int i = 0; i < aSector.length; i++ ) { aSector[i] = new Sector(); }
        aPassword = new Password[shell.getE() -1 + 2];                                              // Passwords one per Ipe/vrg, log & Dir
        for (int i = 0; i < aPassword.length; i++ ) { aPassword[i] = new Password(); }

        byte[] baTmp;
        int iSector = 0;
        baTmp = DecodeJsonByteArray(szJsonCardImage, "baDir");                                      // Dir into a sector
        if (baTmp != null) System.arraycopy(baTmp, 0, aSector[iSector].baBody, 0, baTmp.length);
        hLatest.setDirPage((byte)iSector++);

        baTmp = DecodeJsonByteArray(szJsonCardImage, "baLog");                                      // Log into a sector
        if (baTmp != null) System.arraycopy(baTmp, 0, aSector[iSector].baBody, 0, baTmp.length);
        hLatest.setLogPage((byte)iSector++);

        JSONArray ipeList = szJsonCardImage.getJSONArray("baIpeList");                              // Ipes and Vrgs into sectors
        for (int i = 0; i < ipeList.length(); i++) {
            JSONObject ipe;
            try                     { ipe = ipeList.getJSONObject(i); }
            catch (JSONException e) { ipe = null;                     }
            if (ipe != null && ipe.length() == 2) {
                baTmp = DecodeJsonByteArray(ipe, "baIpe");
                setSector(iSector, baTmp);
                hLatest.setIpePage(i, (byte)iSector++);

                baTmp = DecodeJsonByteArray(ipe, "baVrg");
                setSector(iSector, baTmp);
                hLatest.setVrgPage(i, (byte)iSector++);
            } else {
                hLatest.setIpePage(i, (byte)iSector++);
                hLatest.setVrgPage(i, (byte)iSector++);
            }
        }
        for (int i = 0; i < sFREE_PAGE_COUNT; i++) {                                                // Free pages into sectors
            hLatest.setFreePage(i, (byte)iSector++);
        }

        JSONArray pwdList = szJsonCardImage.getJSONArray("PasswordList");                           // Passwords into sectors
        for (int i = 0; i < pwdList.length(); i++) {
            baTmp = Base64.decode(pwdList.getString(i), Base64.DEFAULT);
            if (baTmp != null) System.arraycopy(baTmp, 0, aPassword[i].baBody, 0, baTmp.length);
        }
        // If we are successful the caller will erase the old image and then call SaveImage().
        //
    }

    // ========================================
    // JsonExport()
    //      Save the CM image to the NVM store.
    // ========================================
    public JSONObject  JsonExport() {                                                               // Make a Json String of the CM Image
        Log.d(TAG, "JsonExport");
        // ToDo: create the Json file contents here.
        return null;
    }




    public  void setSector(int iIndex, byte[] baBlob) throws VirtualCardException {                                         // Set a sector's contents.
        if (iIndex < 0 || iIndex >= aSector.length) throw new VirtualCardException("setSector: Invalid Sector Index");      //
        if (baBlob != null) System.arraycopy(baBlob, 0, aSector[iIndex].baBody, 0, min(baBlob.length, sPAGE_SIZE));         //
    }                                                                                                                       //

    public byte[] getSector(int iIndex) throws VirtualCardException {                                                      // Get a sector's contents.
        if (iIndex < 0 || iIndex >= aSector.length) throw new VirtualCardException("getSector: Invalid Sector Index");      //
        return aSector[iIndex].baBody;                                                                                      //
    }




    // ========================================
    // Reset()
    //      clear/init working variables.
    //      return the FCI
    // ========================================
    public void Reset() throws VirtualCardException {                                               // Card reset
        Log.d(TAG, "Reset");
        // ToDo: Clear CM Ram vars here.

        Arrays.fill(baChallenge,     (byte)0);
        Arrays.fill(baChallengeTemp, (byte)0);
        fAuthenticated       = false;
        fPseudoAuthenticated = false;
        sFciStart            = 0;
        sFciA5LenOffset      = 0;
        sAllocated           = 0;

        MmmtA.Load();
        MmmtB.Load();
        boolean fA = MmmtA.checkCrc();
        boolean fB = MmmtB.checkCrc();

        if (fA && fB) {                                                                             // both good
            if (MmmtA.getTsn() > MmmtB.getTsn()) {  hLatest = MmmtA; hOldest = MmmtB; }            //      A = most recent
            else                                 {  hLatest = MmmtB; hOldest = MmmtA; }            //      B = most recent
        }
        else if (MmmtA.checkCrc())               {  hLatest = MmmtA; hOldest = MmmtB; }            // A ok, B bad
        else if (MmmtB.checkCrc() )              {  hLatest = MmmtB; hOldest = MmmtA; }            // B ok, A bad
        else {                                                                                      // both bad!!! should not happen
            throw new VirtualCardException("A & B copies of memory are bad");
        }

    }

    // ========================================
    // Select()
    //      construct and return the FCI
    // ========================================
    public byte[] Select() {                                                                        // Card select
        Log.d(TAG, "Select");                                                                       // Build FCI.A5's contents
        try {
            Reset();                                                                                // Clear on reset//select variables initialized.
        }
        catch (VirtualCardException e) {
            Log.d(TAG, "Select: + " + e.getMessage() );
            return new byte[] { (byte)0x80, 1, 11};
        }

        // ToDo: Build the FCI A5 contents here
        return new byte[] { (byte)0x80, 1, 11};
    }

    // ========================================
    // Dispatch()
    //      process the APDU
    // ========================================
    public byte[] Dispatch(byte[] baApdu) {                                                         // Card dispatch
        Log.d(TAG, "Dispatch");
        // ToDo: Process APDUs here.
        return Response(SW.INS_NOT_SUPPORTED);
    }

}
