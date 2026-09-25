package com.digitallocksmiths.ItsoHce.VcardCmd12;

import android.util.Log;

import com.digitallocksmiths.ItsoHce.VCard;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;

import org.json.JSONException;
import org.json.JSONObject;

//import java.util.Base64;


public class Cmd12 extends VCard {
    private static final String TAG = "Cmd12";

    private JSONObject szCardImage = null;

        // Constructor
    public Cmd12() { super(); }


    public static  VCard Factory() {                                                                // bootstrap load existing image
        return new Cmd0();
    }

    public static VCard Factory(JSONObject szCardImage) throws JSONException {
        Cmd12 v = new Cmd12();
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
    }

    // ========================================
    // Select()
    //      construct and return the FCI
    // ========================================
    public byte[] Select() {                                                                        // Card select
        Log.d(TAG, "Application Select");
        return Response( new byte[] { 12 }, SW.NO_ERROR);
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
