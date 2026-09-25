package com.digitallocksmiths.ItsoHce.VcardCmd2;

import android.util.Log;

import com.digitallocksmiths.ItsoHce.VCard;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;

import org.json.JSONObject;



public class Cmd2 extends VCard {
    private static final String TAG = "Cmd2";

    private JSONObject szCardImage = null;

    // Constructor
    public Cmd2() {
        super();
    }

    public static  VCard Factory() {                                                                // bootstrap load existing image
        return new Cmd2();
    }

    public static  VCard Factory(JSONObject szCardImage) {
        Cmd2 v = new Cmd2();
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
        return Response( new byte[] { 2 }, SW.NO_ERROR);
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
