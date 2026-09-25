package com.digitallocksmiths.ItsoHce.VcardCmd7;

import android.util.Log;

import com.digitallocksmiths.ItsoHce.VCard;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;

import org.json.JSONObject;

import java.util.Arrays;


public class Cmd7 extends VCard {
    private static final String TAG = "Cmd7";

    private JSONObject szCardImage = null;

    // Constructor
    public Cmd7() {
        super();
    }

    public static  VCard Factory() {                                                                // bootstrap load existing image
        return new Cmd7();
    }


    public static VCard Factory(JSONObject szCardImage) {
        Cmd7 v = new Cmd7();
        v.szCardImage = szCardImage;
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
        return;
    }

    // ========================================
    // Select()
    //      construct and return the FCI
    // ========================================
    public byte[] Select() {                                                                        // Card select
        Log.d(TAG, "Application Select");
        return Response( new byte[] { 7 }, SW.NO_ERROR);
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
