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

    private static final byte  bPWD_SIZE        =  16;                                              // Size of Password Data
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
    private Mmmt   mmmt;
    private Password[] aPassword;


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

        mmmt            = new Mmmt(shell.getE());
        aPassword       = new Password[shell.getE()+1];
        for (int i = 0; i < aPassword.length; i++) {
            aPassword[i] = new Password();
        }

    }

    // ========================================
    // ImageGetSize()
    //    Return the size of the serialized image in bytes.
    // ========================================
    protected int   ImageGetSize() {                                                                // subclasses indicate their own storage volume requirements
        Log.d(TAG, "ImageGetSize");
        // ToDo: Sizeof the image here.
        return  SerializeOverhead + baAid.length +
                SerializeOverhead + mAuthDesKeyA.length +
                SerializeOverhead + mAuthDesKeyB.length +
                SerializeOverhead + mAuthPseudoKeyA.length +
                SerializeOverhead + mAuthPseudoKeyB.length +
                SerializeOverhead + baPseudoShell.length +
                SerializeOverhead + baUID.length +
                SerializeOverhead + baPseudoUID.length +
                SerializeOverhead + baAuthKasParams.length +
                mmmt.ImageGetSize() +
                aPassword.length * (SerializeOverhead + bPWD_SIZE);
    };

    // ========================================
    // ImageDeserialize()
    //      Make a new VCard from NVM store.
    // ========================================
    protected void  ImageDeserialize(ByteBuffer buffer) {                                           // subclasses populate their working variables here.
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
        mmmt.ImageDeserialize(buffer);
        for (Password password : aPassword) {
            password.baBody = DeserializeByteArray(buffer);
        }
    }

    // ========================================
    // ImageSerialize()
    //      Add this class's image variables
    //      to the buffer.
    // ========================================
    protected void  ImageSerialize(ByteBuffer buffer) {                                             // subclasses serialize their variables here.
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
        mmmt.ImageSerialize(buffer);
        for (Password password : aPassword) {
            SerializeByteArray(buffer, password.baBody);
        }
    }




    // ========================================
    // JsonParse(JSONObject szJsonCardImage)
    //      Make a new VCard from the JSON image.
    // ========================================
    protected void  JsonParse(JSONObject szJsonCardImage) throws JSONException, VirtualCardException {  // parse the JSON image into the CM Image
        Log.d(TAG, "JsonParse");
        // ToDo: Test this

        byte[] baTmp;

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

        mmmt.setDirPage(DecodeJsonByteArray(szJsonCardImage, "baDir"));                       // Dir into a sector
        mmmt.setLogPage(DecodeJsonByteArray(szJsonCardImage, "baLog"));                       // Log into a sector

        int iSector = 1;
        JSONArray ipeList = szJsonCardImage.getJSONArray("baIpeList");                        // Ipes and Vrgs into sectors
        for (int i = 0; i < ipeList.length(); i++) {                                                // should be E-1 of them.
            JSONObject ipe;
            try                     { ipe = ipeList.getJSONObject(i); }
            catch (JSONException e) { ipe = null;                     }
            if (ipe != null && ipe.length() == 2) {
                mmmt.setIpePage(iSector, DecodeJsonByteArray(ipe, "baIpe"));
                mmmt.setVrgPage(iSector, DecodeJsonByteArray(ipe, "baVrg"));
            }
            iSector++;
        }

        JSONArray pwdList = szJsonCardImage.getJSONArray("PasswordList");                     // Passwords into sectors
        for (int i = 0; i < pwdList.length(); i++) {                                                // should be E of them.
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
    protected JSONObject  JsonExport() {                                                            // Make a Json String of the CM Image
        Log.d(TAG, "JsonExport");
        // ToDo: create the Json file contents here.
        return null;
    }

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
        sAllocated           = 0;

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
    protected byte[] Dispatch(byte[] baApdu) {                                                         // Card dispatch
        Log.d(TAG, "Dispatch");
        // ToDo: Process APDUs here.
        return Response(SW.INS_NOT_SUPPORTED);
    }

}
