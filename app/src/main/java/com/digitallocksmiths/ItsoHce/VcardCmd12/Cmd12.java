package com.digitallocksmiths.ItsoHce.VcardCmd12;

import com.digitallocksmiths.ItsoHce.VCard;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;

import org.json.JSONException;
import org.json.JSONObject;

//import java.util.Base64;


public class Cmd12 extends VCard {

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
    public byte[] Reset() {                                                                         // Card reset
        return new byte[] { 12,12,12,12,12,12,12,12};
    }

}
