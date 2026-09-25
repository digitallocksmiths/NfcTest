package com.digitallocksmiths.ItsoHce.VcardCmd7;

import com.digitallocksmiths.ItsoHce.VCard;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;

import org.json.JSONObject;

import java.util.Arrays;


public class Cmd7 extends VCard {

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
    public byte[] Reset() {                                                                         // Card reset
        return new byte[] { 7,7,7,7,7,7,7,7};
    }

}
