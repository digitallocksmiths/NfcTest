package com.digitallocksmiths.ItsoHce.VcardCmd2;

import com.digitallocksmiths.ItsoHce.VCard;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;

import org.json.JSONObject;



public class Cmd2 extends VCard {

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
    public byte[] Reset() {                                                                         // Card reset
        return new byte[] { 2,2,2,2,2,2,2,2};
    }

}
