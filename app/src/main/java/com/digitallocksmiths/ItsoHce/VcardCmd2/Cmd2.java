package com.digitallocksmiths.ItsoHce.VcardCmd2;

import android.util.Log;

import com.digitallocksmiths.ItsoHce.VCard;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.ByteBuffer;


public class Cmd2 extends VCard {
    private static final String TAG = "Cmd2";

    // Constructor
    public Cmd2()  throws VCard.VirtualCardException {
        super();
        NameSet("CMD 2");
    }

    // ========================================
    // ImageGetSize()
    //    Return the size of the serialized image in bytes.
    // ========================================
    public int      ImageGetSize() {                                                                // subclasses indicate their own storage volume requirements
        Log.d(TAG, "ImageGetSize");
        return 0;
    };

    // ========================================
    // ImageDeserialize()
    //      Make a new VCard from NVM store.
    // ========================================
    protected void  ImageDeserialize(ByteBuffer buffer) {                                           // subclasses populate their working variables here.
        Log.d(TAG, "ImageDeserialize");
        // ToDo: Read the files into the subclass's image variables.
    }

    // ========================================
    // ImageSerialize()
    //      Add this class's image variables
    //      to the buffer.
    // ========================================
    protected void  ImageSerialize(ByteBuffer buffer) {                                             // subclasses serialize their variables here.
        Log.d(TAG, "ImageSerialize");
        // ToDo: Serialize the image here.
    }

    // ========================================
    // JsonParse(JSONObject szJsonCardImage)
    //      populate the VCARD from the JSON
    //      input.
    // ========================================
    protected void  JsonParse(JSONObject jsonCardImage) throws JSONException, VirtualCardException {  // parse the JSON image into the CM Image.
        Log.d(TAG, "JsonParse");
        // ToDo: Read the Json image here.
    }

    // ========================================
    // JsonExport()
    //      Save the CM image to the NVM store.
    // ========================================
    protected void  JsonExport(JSONObject jsonCardImage) {                                          // Add data to the JSON object.
        Log.d(TAG, "JsonExport");
        // ToDo: create the Json file contents here.
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
    protected byte[] Dispatch(byte[] baApdu) {                                                         // Card dispatch
        Log.d(TAG, "Dispatch");
        // ToDo: Process APDUs here.
        return Response(SW.INS_NOT_SUPPORTED);
    }


}
