package com.digitallocksmiths.ItsoHce.VcardCmd11;

import android.util.Base64;
import android.util.Log;

import com.digitallocksmiths.ItsoHce.VCard;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;


public class Cmd11 extends VCard {
    private static final String TAG = "Cmd11";

    private JSONObject szJsonCardImage = null;

    private byte[] baAid;
    private byte[] baAuthKasParams;
    private byte[] baUID;
    private byte[] baShell;
    private byte[] mAuthDesKeyA;
    private byte[] mAuthDesKeyB;
    private byte[] baPseudoUID;
    private byte[] baPseudoShell;
    private byte[] mAuthPseudoKeyA;
    private byte[] mAuthPseudoKeyB;



    private static final byte  bCHAL_SIZE   = 8;                                                    // Size of Random Challenge Data

    // ==========================================================================
    // Clear on reset variables

    public byte[]  baChallenge          = new byte[bCHAL_SIZE];
    public byte[]  baChallengeTemp      = new byte[bCHAL_SIZE];
    public boolean fAuthenticated       = false;                                                                 // Bool vars
    public boolean fPseudoAuthenticated = false;
    public byte    bDummy               = 0;                                                                             // Byte vars
    public short   sFciStart            = 0;                                                                          // Short vars
    public short   sFciA5LenOffset      = 0;
    public short   sAllocated           = 0;
    public Mmmt    hMmmt                = new Mmmt();                                                           // Ram working mmmt
    public Mmmt    hLatests             = null;            /* nay be changed for the szFileName ? */                   // Object vars
    public Mmmt    hOldest              = null;

    // ==========================================================================
    // NV varables

    public static String        szMmmtA = "MmmtA";                                                  //
    public static String        szMmmtB = "MmmtB";                                                  //

//  public static RandomData    Rng;                                                                // Shared Random generator.
//  public static Checksum      Crc;                                                                //        CRC resource.
//  public static Cipher        Cip;                                                                // 		  challenge processor/SK generator.
//  public static Signature     Sig;                                                                // 		  MAC verifyer/generator.
//  public static DESKey        SessionKey;                                                         //        ephemeral (transient) session key.
//  public static MessageDigest Hash;                                                               //		  Apdu Message disest.

    // Constructor
    public Cmd11() {
        super();
    }

    // ========================================
    // FactoryLoadImage()
    //      Make a new VCard from NVM store.
    // ========================================
    public static  VCard FactoryLoadImage() {                                                       // bootstrap load existing image from NVM store
        Log.d(TAG, "FactoryLoadImage");
        Cmd11 cmd = new Cmd11();
        cmd.szTitle = "Uninitialized CMD11 Card Image";
        // ToDo: Read the files into the image here.
        return cmd;
    }


    // ========================================
    // FactoryImportImage(JSONObject szJsonCardImage)
    //      Make a new VCard from the JSON image.
    // ========================================
    public static VCard FactoryImportImage(JSONObject szJsonCardImage) throws JSONException {
        Cmd11 v = new Cmd11();
        v.szJsonCardImage = szJsonCardImage;
        try {
            v.baAid           = Base64.decode(szJsonCardImage.getString("baAid"),           Base64.DEFAULT);
            v.baAuthKasParams = Base64.decode(szJsonCardImage.getString("baAuthKasParams"), Base64.DEFAULT);
            v.baUID           = Base64.decode(szJsonCardImage.getString("baUID"),           Base64.DEFAULT);
            v.baShell         = Base64.decode(szJsonCardImage.getString("baShell"),         Base64.DEFAULT);
            v.mAuthDesKeyA    = Base64.decode(szJsonCardImage.getString("mAuthDesKeyA"),    Base64.DEFAULT);
            v.mAuthDesKeyB    = Base64.decode(szJsonCardImage.getString("mAuthDesKeyB"),    Base64.DEFAULT);
            v.baPseudoUID     = Base64.decode(szJsonCardImage.getString("baPseudoUID"),     Base64.DEFAULT);
            v.baPseudoShell   = Base64.decode(szJsonCardImage.getString("baPseudoShell"),   Base64.DEFAULT);
            v.mAuthPseudoKeyA = Base64.decode(szJsonCardImage.getString("mAuthPseudoKeyA"), Base64.DEFAULT);
            v.mAuthPseudoKeyB = Base64.decode(szJsonCardImage.getString("mAuthPseudoKeyB"), Base64.DEFAULT);
            // ToDo: Read the Json image here.

        }
        catch (JSONException e) {
            throw(e);
        }
        catch (Exception e) {
            throw(e);
        }

        return v;
    }


    // ========================================
    // SaveImage()
    //      Save the CM image to the NVM store.
    // ========================================
    public void        SaveImage() {                                                                // Save the CM image to the NVM store.
        Log.d(TAG, "SaveImage");
        // ToDo: Save the image to files here.
    }

    // ========================================
    // ExportImage()
    //      Make a JSON image of the CM.
    // ========================================
    public JSONObject ExportImage() {                                                               // CM image to Json.
        Log.d(TAG, "ExportImage");
        // ToDo: Make the Json file contents here.
        return szJsonCardImage;
    }

    // ========================================
    // Reset()
    //      clear/init working variables.
    //      return the FCI
    // ========================================
    public void Reset() {                                                                           // Card reset
        Log.d(TAG, "Reset");
        // ToDo: Clear CM Ram vars here.

        Arrays.fill(baChallenge,     (byte)0);
        Arrays.fill(baChallengeTemp, (byte)0);
        fAuthenticated       = false;
        fPseudoAuthenticated = false;
        sFciStart            = 0;
        sFciA5LenOffset      = 0;
        sAllocated           = 0;
        //hMmmt                = new Mmmt((byte)0);
        //hLatests             = null;
        //hOldest              = null;

    }

    // ========================================
    // Select()
    //      construct and return the FCI
    // ========================================
    public byte[] Select() {                                                                        // Card select
        Log.d(TAG, "Select");                                                                       // Build FCI.A5's contents
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
