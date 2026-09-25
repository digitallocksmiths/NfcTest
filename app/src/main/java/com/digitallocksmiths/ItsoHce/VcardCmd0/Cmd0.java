package com.digitallocksmiths.ItsoHce.VcardCmd0;

import com.digitallocksmiths.ItsoHce.Itso.Shell;
import com.digitallocksmiths.ItsoHce.VCard;

import org.json.JSONObject;


public class Cmd0 extends VCard {

    private JSONObject szCardImage = null;

    // Constructor
    public Cmd0() {
        super();
        baShell = new byte[] { 24, 1, 99, 53, -105, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 54 };            // FVC 0 shell
        shell   = new Shell(baShell);
    }


    public static  VCard Factory() {                                                                // bootstrap load existing image
        Cmd0 cmd = new Cmd0();
        cmd.szTitle = "Uninitialized Card Image";
        return cmd;
    }

    public static  VCard Factory(JSONObject szCardImage) {                                          // new image from Json template
        //com.digitallocksmiths.ItsoHce.VcardCmd2.Cmd2 v = new com.digitallocksmiths.ItsoHce.VcardCmd2.Cmd2();
        Cmd0 v = new Cmd0();
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
