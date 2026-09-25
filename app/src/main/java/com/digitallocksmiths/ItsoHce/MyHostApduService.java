package com.digitallocksmiths.ItsoHce;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

public class MyHostApduService extends HostApduService {
    private static final String TAG = "MyHostApduService";

    // Response for "SELECT AID"
    private static final byte[] SELECT_OK_SW = {(byte) 0x90, (byte) 0x00};
    private static final byte[] UNKNOWN_CMD_SW = {(byte) 0x6E, (byte) 0x00};


    @Override
    public void onCreate() {                                                                        // create service
        super.onCreate();
        Log.d(TAG, "Service created");
    }

    @Override
    public void onDestroy() {                                                                       // destroy service
        super.onDestroy();
        Log.d(TAG, "Service destroyed");
    }

    @Override
    public void onDeactivated(int reason) {                                                         // deselect or deactivate
        Log.d(TAG, "Service deactivated: " + reason);
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {                           // process command
        if (commandApdu == null) {
            return UNKNOWN_CMD_SW;
        }

        String hexCommand = bytesToHex(commandApdu);
        Log.d(TAG, "Received APDU: " + hexCommand);

        // Check if it's a SELECT AID command
        // The first 4 bytes 00 A4 04 00 are standard for SELECT AID
        if (commandApdu.length >= 4 && commandApdu[0] == (byte) 0x00 && commandApdu[1] == (byte) 0xA4 
                && commandApdu[2] == (byte) 0x04 && commandApdu[3] == (byte) 0x00) {
            Log.d(TAG, "SELECT AID detected");
            return SELECT_OK_SW;
        }

        // Add more logic here to handle other commands
        return SELECT_OK_SW;
    }




    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}