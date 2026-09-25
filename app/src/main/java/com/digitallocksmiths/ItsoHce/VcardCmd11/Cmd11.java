package com.digitallocksmiths.ItsoHce.VcardCmd11;

import android.util.Base64;
import android.util.Log;

import com.digitallocksmiths.ItsoHce.NvmFile;
import com.digitallocksmiths.ItsoHce.VCard;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;

import org.json.JSONException;
import org.json.JSONObject;

import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.zip.Checksum;

import javax.crypto.Cipher;


public class Cmd11 extends VCard {
    private static final String TAG = "Cmd11";

    private JSONObject szCardImage = null;

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

    public static  VCard Factory() {                                                                // bootstrap load existing image
        return new Cmd11();
    }


    public static VCard Factory(JSONObject szCardImage) throws JSONException {
        Cmd11 v = new Cmd11();
        v.szCardImage = szCardImage;
        try {
            v.baAid           = Base64.decode(szCardImage.getString("baAid"),           Base64.DEFAULT);
            v.baAuthKasParams = Base64.decode(szCardImage.getString("baAuthKasParams"), Base64.DEFAULT);
            v.baUID           = Base64.decode(szCardImage.getString("baUID"),           Base64.DEFAULT);
            v.baShell         = Base64.decode(szCardImage.getString("baShell"),         Base64.DEFAULT);
            v.mAuthDesKeyA    = Base64.decode(szCardImage.getString("mAuthDesKeyA"),    Base64.DEFAULT);
            v.mAuthDesKeyB    = Base64.decode(szCardImage.getString("mAuthDesKeyB"),    Base64.DEFAULT);
            v.baPseudoUID     = Base64.decode(szCardImage.getString("baPseudoUID"),     Base64.DEFAULT);
            v.baPseudoShell   = Base64.decode(szCardImage.getString("baPseudoShell"),   Base64.DEFAULT);
            v.mAuthPseudoKeyA = Base64.decode(szCardImage.getString("mAuthPseudoKeyA"), Base64.DEFAULT);
            v.mAuthPseudoKeyB = Base64.decode(szCardImage.getString("mAuthPseudoKeyB"), Base64.DEFAULT);




        }
        catch (JSONException e) {
            throw(e);
        }
        catch (Exception e) {
            throw(e);
        }

        return v;
    }


    public JSONObject CreateImage() {
        return szCardImage;
    }

     // ========================================
    // Reset()
    //      clear/init working variables.
    //      return the FCI
    // ========================================
    public void Reset() {                                                                           // Card reset
        Log.d(TAG, "Card reset");

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
        Log.d(TAG, "Application Select");
        return Response( new byte[] { 11 }, SW.NO_ERROR);
    }

    // ========================================
    // Dispatch()
    //      process the APDU
    // ========================================
    public byte[] Dispatch(byte[] baApdu) {                                                         // Card dispatch
        Log.d(TAG, "Application Dispatch");
        return Response(SW.INS_NOT_SUPPORTED);
    }

}
