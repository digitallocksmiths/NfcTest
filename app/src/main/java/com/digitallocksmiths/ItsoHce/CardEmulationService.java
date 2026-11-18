package com.digitallocksmiths.ItsoHce;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.io.File;
import java.util.Objects;

public class CardEmulationService extends HostApduService {
    private static final String TAG = "MyHostApduService";


    private VCard vcard;                                                                            // Card image loaded on create.


    // =============================================================================================
    // File helpers
    //
    private String GetAppPrivateDirectory() {
        return getFilesDir().getPath();
    }                                         // this is where secret files are stored.

    private String GetAppPublicDirectory() {
        return Objects.requireNonNull(getExternalFilesDir(null)).getPath();
    }     // this is where the json profiles are stored.

    private String GetImageDirectory() {
        return GetAppPrivateDirectory() + File.separator + "Image";
    }             // this is where the images are stored.


    @Override
    public void onCreate() {                                                                        // create service
        super.onCreate();
        Log.d(TAG, "Service created");
        try {
            VCard.Initialize(GetImageDirectory());                                                  // set up the classes NVM (once only)
        } catch (VCard.VirtualCardException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void onDeactivated(int reason) {                                                         // link loss (field off) or deselect
        Log.d(TAG, "Service deactivated: " + reason);
        if (vcard != null) {                                                                        // end of session:
            vcard.Dispose();                                                                        //      scrub the secrets
            vcard = null;                                                                           //      drop the image so the next SELECT reloads it
        }
    }

    @Override
    public void onDestroy() {                                                                       // destroy service
        super.onDestroy();
        Log.d(TAG, "Service destroyed");
    }



    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {                           // process command

        Log.d(TAG, "Received APDU: " + VCard.bytesToHex(commandApdu));
        byte[] baResponse;// = null;

        Apdu apdu = new Apdu(commandApdu);

        if (apdu.apduCase == Apdu.ApduCase.Malformed) {
            return Apdu.BuildResponse(Apdu.SW.CLA_NOT_SUPPORTED);
        }


        if (apdu.Cla ==  0x00 &&                                                                    // Check if it's a SELECT AID command
            apdu.Ins ==  0xA4 &&
            apdu.P1  ==  0x04 &&
            apdu.P2  ==  0x00 &&
            apdu.Lc >  0) {
            Log.d(TAG, "SELECT AID detected");
                try {
                    if (vcard != null) {                                                            // a (re)select is a warm reset:
                        vcard.Dispose();                                                            //      scrub the current image
                        vcard = null;
                    }
                    vcard = VCard.FactoryImageLoad(VCard.ActiveCardGet());                          //      reload the active card's image
                    vcard.Reset();                                                                  //      and clear the 'RAM' variables
                    byte[] baFci    = vcard.Select(apdu.baRxData);                                  // Do the selection and get the FCI in response.
                    baResponse =  Apdu.BuildResponse(baFci, Apdu.SW.NO_ERROR);                          // return it with the happy message.
                }
                catch (VCard.VirtualCardException e) {
                    Log.d(TAG, "SELECT failed: " + e.getMessage());
                    if (vcard != null) {                                                            // don't run on a half-loaded image
                        vcard.Dispose();
                        vcard = null;
                    }
                    baResponse =  Apdu.BuildResponse(Apdu.SW.APPLET_SELECT_FAILED);
                } catch (VCard.VCardIntegrityException e) {
                    throw new RuntimeException(e);
                }
        }
        else if (vcard == null) {
            baResponse =  Apdu.BuildResponse(Apdu.SW.CLA_NOT_SUPPORTED);
        }
        else {
            try {
                vcard.Dispatch(apdu);                                                               // Dispatch and expect return via ApduExitException
                baResponse =  Apdu.BuildResponse(Apdu.SW.UNKNOWN);                                       // This should not happen.
            }
            catch (Apdu.ExitException e) {
                baResponse = e.GetResponse();
            }
            catch (VCard.VCardIntegrityException e) {
                throw new RuntimeException(e);
            }

        }

        Log.d(TAG, "Response:      " + VCard.bytesToHex(baResponse));
        return baResponse;

    }

}