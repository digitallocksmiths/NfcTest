package com.digitallocksmiths.ItsoHce;

import static java.lang.System.arraycopy;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.io.File;
import java.util.Arrays;
import java.util.Objects;

public class MyHostApduService extends HostApduService {
    private static final String TAG = "MyHostApduService";


    private VCard vcard;                                                                            // Card image loaded on create.


    // =============================================================================================
    // File helpers
    //
    private String GetAppPrivateDirectory() { return getFilesDir().getPath(); }                                         // this is where secret files are stored.
    private String GetAppPublicDirectory()  { return Objects.requireNonNull(getExternalFilesDir(null)).getPath(); }     // this is where the json profiles are stored.
    private String GetImageDirectory()      { return GetAppPublicDirectory() + File.separator + "Image"; }              // this is where the image will be stored.



    @Override
    public void onCreate() {                                                                        // create service
        super.onCreate();
        Log.d(TAG, "Service created");
        VCard.Initialize(GetImageDirectory());                                                      // set up the classes NVM
        vcard = VCard.FactoryLoadImage();                                                           // load the CM image.
    }

    @Override
    public void onDeactivated(int reason) {                                                         // deselect or deactivate
        Log.d(TAG, "Service deactivated: " + reason);
        vcard.Reset();
    }

    @Override
    public void onDestroy() {                                                                       // destroy service
        super.onDestroy();
        Log.d(TAG, "Service destroyed");
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {                           // process command
        if (commandApdu == null) {
            return VCard.Response(VCard.SW.CLA_NOT_SUPPORTED);
        }

        String hexCommand = bytesToHex(commandApdu);
        Log.d(TAG, "Received APDU: " + hexCommand);

        // Check if it's a SELECT AID command
        // The first 4 bytes 00 A4 04 00 are standard for SELECT AID
        if (commandApdu.length >= 4       &&
            commandApdu[0] == (byte) 0x00 &&
            commandApdu[1] == (byte) 0xA4 &&
            commandApdu[2] == (byte) 0x04 &&
            commandApdu[3] == (byte) 0x00)    {
                Log.d(TAG, "SELECT AID detected");
                byte[] baAid    = Arrays.copyOfRange(commandApdu, 5, 5 + commandApdu[4]);           // 84 : AID
                byte[] baA5Body = vcard.Select();                                                   // A5 : Propitiatory

                boolean fA5_Long = (baA5Body.length > 127);
                boolean f6F_Long = ((2 + baAid.length + ((fA5_Long)?3:2) + baA5Body.length) > 127);

                byte[] baFci     = new byte[((f6F_Long) ? 3:2) +
                                            (2 + baAid.length) +
                                            ((fA5_Long)?3:2)   +
                                             baA5Body.length];

                int iOffset=0;
                baFci[iOffset++] = 0x6F;                                                            // 6F : FCI tag
                if (f6F_Long) { baFci[iOffset++] = (byte)0x81; }                                    //    len opt
                baFci[iOffset++] = (byte)(baFci.length-iOffset);                                    //    len
                baFci[iOffset++] = (byte)0x84;                                                      //        84 : tag
                baFci[iOffset++] = (byte)baAid.length;                                              //           len
                arraycopy(baAid, 0, baFci, iOffset, baAid.length);                                  //           body
                iOffset += baAid.length;                                                            //
                baFci[iOffset++] = (byte)0xa5;                                                      //        A5 : tag
                if (fA5_Long) { baFci[iOffset++] = (byte) 0x81; }                                   //           len opt
                baFci[iOffset++] = (byte)baA5Body.length;                                           //           len
                arraycopy(baA5Body, 0, baFci, iOffset, baA5Body.length);                            //           body
                iOffset += baA5Body.length;                                                         //

                return VCard.Response(baFci, VCard.SW.NO_ERROR);                                    // return it with the happy message.
        }

        return vcard.Dispatch(commandApdu);
    }




    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}