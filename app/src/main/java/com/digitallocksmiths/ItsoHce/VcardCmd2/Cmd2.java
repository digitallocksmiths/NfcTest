package com.digitallocksmiths.ItsoHce.VcardCmd2;

import android.util.Log;

import com.digitallocksmiths.ItsoHce.VCard;

import org.json.JSONObject;



public class Cmd2 extends VCard {
    private static final String TAG = "Cmd2";

    private JSONObject szJsonCardImage = null;

    // Constructor
    public Cmd2() {
        super();
    }


    // ========================================
    // FactoryLoadImage()
    //      Make a new VCard from NVM store.
    // ========================================
    public static  VCard FactoryLoadImage() {                                                       // bootstrap load existing image from NVM store
        Log.d(TAG, "FactoryLoadImage");
        // ToDo: Read the files into the image here.
        Cmd2 cmd = new Cmd2();
        cmd.szTitle = "Uninitialized CMD2 Card Image";
        return cmd;
    }

    // ========================================
    // FactoryImportImage(JSONObject szJsonCardImage)
    //      Make a new VCard from the JSON image.
    // ========================================
    public static  VCard FactoryImportImage(JSONObject szJsonCardImage) {                           // new image from Json template
        Log.d(TAG, "FactoryImportImage");
        // ToDo: Read the Json image here.
        Cmd2 v = new Cmd2();
        v.szJsonCardImage = szJsonCardImage;
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
        // ToDo: Clear CM Ram vars here.
        Log.d(TAG, "Reset");
    }


    // ========================================
    // Select()
    //      construct and return the FCI
    // ========================================
     public byte[] Select() {                                                                        // Card select
         Log.d(TAG, "Select");                                                                       // Build FCI.A5's contents
         // ToDo: Build the FCI A5 contents here.
         return new byte[] { (byte)0x80, 1, 2};
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
