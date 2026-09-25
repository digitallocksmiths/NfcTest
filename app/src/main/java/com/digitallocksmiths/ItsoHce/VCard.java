package com.digitallocksmiths.ItsoHce;


import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

import org.json.JSONException;
import org.json.JSONObject;

import com.digitallocksmiths.ItsoHce.Itso.Shell;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;
import com.digitallocksmiths.ItsoHce.VcardCmd2.Cmd2;
import com.digitallocksmiths.ItsoHce.VcardCmd7.Cmd7;
import com.digitallocksmiths.ItsoHce.VcardCmd11.Cmd11;
import com.digitallocksmiths.ItsoHce.VcardCmd12.Cmd12;

public abstract class VCard {

    public static class VirtualCardException extends Exception {                                    // our type of exception
        public VirtualCardException(String szMsg) {
            super(szMsg);
        }
    }

    public static class SW {                                                                        // Status words
        public static final short NO_ERROR                       = (short)0x9000;     // No Error
        public static final short BYTES_REMAINING_00             = (short)0x6100;     // Response bytes remaining
        public static final short WRONG_LENGTH                   = (short)0x6700;     // Wrong length
        public static final short SECURITY_STATUS_NOT_SATISFIED  = (short)0x6982;     // Security condition not satisfied
        public static final short FILE_INVALID                   = (short)0x6983;     // File invalid
        public static final short DATA_INVALID                   = (short)0x6984;     // Data invalid
        public static final short CONDITIONS_NOT_SATISFIED       = (short)0x6985;     // Conditions of use not satisfied
        public static final short COMMAND_NOT_ALLOWED            = (short)0x6986;     // Command not allowed (no current EF)
        public static final short APPLET_SELECT_FAILED           = (short)0x6999;     // Applet selection failed
        public static final short WRONG_DATA                     = (short)0x6A80;     // Wrong data
        public static final short FUNC_NOT_SUPPORTED             = (short)0x6A81;     // Function not supported
        public static final short FILE_NOT_FOUND                 = (short)0x6A82;     // File not found
        public static final short RECORD_NOT_FOUND               = (short)0x6A83;     // Record not found
        public static final short INCORRECT_P1P2                 = (short)0x6A86;     // Incorrect parameters (P1,P2)
        public static final short WRONG_P1P2                     = (short)0x6B00;     // Incorrect parameters (P1,P2)
        public static final short CORRECT_LENGTH_00              = (short)0x6C00;     // Correct Expected Length (Le)
        public static final short INS_NOT_SUPPORTED              = (short)0x6D00;     // INS value not supported
        public static final short CLA_NOT_SUPPORTED              = (short)0x6E00;     // CLA value not supported
        public static final short UNKNOWN                        = (short)0x6F00;     // No precise diagnosis
        public static final short FILE_FULL                      = (short)0x6A84;     // Not enough memory space in the file
        public static final short LOGICAL_CHANNEL_NOT_SUPPORTED  = (short)0x6881;     // Card does not support the operation on the specified logical channel
        public static final short SECURE_MESSAGING_NOT_SUPPORTED = (short)0x6882;     // Card does not support secure messaging
        public static final short WARNING_STATE_UNCHANGED        = (short)0x6200;     // Warning, card state unchanged
        public static final short LAST_COMMAND_EXPECTED          = (short)0x6883;     // Last command in chain expected
        public static final short COMMAND_CHAINING_NOT_SUPPORTED = (short)0x6884;     // Command chaining not supported

    }

    public static byte[] Response(short sSW) {                                                      // Helper for empty response construction
        byte[] baResponse = new byte[2];
        baResponse[0] = (byte)(sSW >> 8);
        baResponse[1] = (byte)(sSW);
        return baResponse;
    }

    public static byte[] Response(byte[] baData, short sSW) {                                       // Helper for data + response construction
        byte[] baResponse = new byte[baData.length + 2];
        System.arraycopy(baData, 0, baResponse, 0, baData.length);
        baResponse[baData.length] = (byte)(sSW >> 8);
        baResponse[baData.length + 1] = (byte)(sSW);
        return baResponse;
    }



    public String szTitle           = null;
    public String szName            = null;
    public String szFilename        = null;
    public String szSavedAsFilename = null;

    protected static NvmFile    Nvm;
    protected static byte[]     baShell;
    public    static Shell      shell;

    public static VCard Factory(String szImageDirectory) {                                          // power up card
        Nvm      = new NvmFile(szImageDirectory);
        baShell  = Nvm.Read("Shell");                                                               // looking for the image Shell
        try {
            if (baShell != null) {
                shell = new Shell(baShell);
                switch (shell.getFvc()) {
                    case 0x00:  return Cmd0.Factory();
                    case 0x02:  return Cmd2.Factory();
                    case 0x07:  return Cmd7.Factory();
                    case 0x0B:  return Cmd11.Factory();
                    case 0x0C:  return Cmd12.Factory();
                    //default:    return Cmd0.Factory();
                }
            }
            else {
                VCard vcard = Cmd0.Factory();
                Nvm.Write("Shell", baShell);
                return vcard;
            }
        }
        catch(Exception e){ ;
            Log.d("VCard",  e.getMessage());
        }
        return null;
    }



    public static VCard ReInitialize(String szFilename) throws VirtualCardException {               // erase old image and create new one from Json description.
        File   file;
        String szJson;
        JSONObject jsonCardImage;
        try {
            file = new File(szFilename);
            Scanner scanner = new Scanner(file, "UTF-8");
            szJson = scanner.useDelimiter("\\A").next();
            jsonCardImage = new JSONObject(szJson);
            scanner.close();
        } catch (IOException e) {
            throw new VirtualCardException("Error opening file: " + szFilename);
        }
        catch (JSONException e) {
            throw new VirtualCardException("Error parsing Json: " + szFilename);
        }

        try {
            VCard newVcard;
            String szName = jsonCardImage.getString("szName");
            if      (szName.equals("CMD2"))  {  newVcard = Cmd2.Factory(jsonCardImage);  }
            else if (szName.equals("CMD7"))  {  newVcard = Cmd7.Factory(jsonCardImage);  }
            else if (szName.equals("CMD11")) {  newVcard = Cmd11.Factory(jsonCardImage); }
            else if (szName.equals("CMD12")) {  newVcard = Cmd12.Factory(jsonCardImage); }
            else {
                throw new VirtualCardException("Unknown card type: " + szName);
            }
            newVcard.szName     = szName;
            newVcard.szFilename = file.getName();
            return newVcard;
        }
        catch (JSONException e) {
            throw new VirtualCardException("Error parsing Json: " + szFilename);
        }
    }


    public boolean SaveImage(String szFilename) throws VirtualCardException {
        JSONObject jsonCardImage = CreateImage();
        String szCardImage = jsonCardImage.toString();
        File file = new File(szFilename);
        try {
            file.createNewFile();
            FileWriter writer = new FileWriter(file);
            writer.write(szCardImage);
            writer.close();
            szSavedAsFilename = file.getName();
        } catch (IOException e) {
            throw new VirtualCardException("Error writing file: " + szFilename);
        }

        return true;
    };


    public abstract JSONObject CreateImage();
    public abstract void       Reset();
    public abstract byte[]     Select();
    public abstract byte[]     Dispatch(byte[] baApdu);

}
