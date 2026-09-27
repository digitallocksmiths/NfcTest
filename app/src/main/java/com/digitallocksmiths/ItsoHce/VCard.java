package com.digitallocksmiths.ItsoHce;

import android.util.Base64;
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
        public static final short NO_ERROR                       = (short)0x9000;                   // No Error
        public static final short BYTES_REMAINING_00             = (short)0x6100;                   // Response bytes remaining
        public static final short WRONG_LENGTH                   = (short)0x6700;                   // Wrong length
        public static final short SECURITY_STATUS_NOT_SATISFIED  = (short)0x6982;                   // Security condition not satisfied
        public static final short FILE_INVALID                   = (short)0x6983;                   // File invalid
        public static final short DATA_INVALID                   = (short)0x6984;                   // Data invalid
        public static final short CONDITIONS_NOT_SATISFIED       = (short)0x6985;                   // Conditions of use not satisfied
        public static final short COMMAND_NOT_ALLOWED            = (short)0x6986;                   // Command not allowed (no current EF)
        public static final short APPLET_SELECT_FAILED           = (short)0x6999;                   // Applet selection failed
        public static final short WRONG_DATA                     = (short)0x6A80;                   // Wrong data
        public static final short FUNC_NOT_SUPPORTED             = (short)0x6A81;                   // Function not supported
        public static final short FILE_NOT_FOUND                 = (short)0x6A82;                   // File not found
        public static final short RECORD_NOT_FOUND               = (short)0x6A83;                   // Record not found
        public static final short INCORRECT_P1P2                 = (short)0x6A86;                   // Incorrect parameters (P1,P2)
        public static final short WRONG_P1P2                     = (short)0x6B00;                   // Incorrect parameters (P1,P2)
        public static final short CORRECT_LENGTH_00              = (short)0x6C00;                   // Correct Expected Length (Le)
        public static final short INS_NOT_SUPPORTED              = (short)0x6D00;                   // INS value not supported
        public static final short CLA_NOT_SUPPORTED              = (short)0x6E00;                   // CLA value not supported
        public static final short UNKNOWN                        = (short)0x6F00;                   // No precise diagnosis
        public static final short FILE_FULL                      = (short)0x6A84;                   // Not enough memory space in the file
        public static final short LOGICAL_CHANNEL_NOT_SUPPORTED  = (short)0x6881;                   // Card does not support the operation on the specified logical channel
        public static final short SECURE_MESSAGING_NOT_SUPPORTED = (short)0x6882;                   // Card does not support secure messaging
        public static final short WARNING_STATE_UNCHANGED        = (short)0x6200;                   // Warning, card state unchanged
        public static final short LAST_COMMAND_EXPECTED          = (short)0x6883;                   // Last command in chain expected
        public static final short COMMAND_CHAINING_NOT_SUPPORTED = (short)0x6884;                   // Command chaining not supported
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

    protected static Nvm Nvm;
    protected static byte[]     baShell;
    public    static Shell      shell;

    public static void Initialize(String szImageDirectory) {                                        // setup the NVM store used by CM images.
        Nvm      = new Nvm(szImageDirectory);
    }


    public static VCard FactoryLoadImage() {                                                        // power up card
        baShell  = Nvm.Read("Shell");                                                               // looking for the image Shell
        try {
            if (baShell != null) {
                shell = new Shell(baShell);
                switch (shell.getFvc()) {
                    case 0x00:  return Cmd0.FactoryLoadImage();
                    case 0x02:  return Cmd2.FactoryLoadImage();
                    case 0x07:  return Cmd7.FactoryLoadImage();
                    case 0x0B:  return Cmd11.FactoryLoadImage();
                    case 0x0C:  return Cmd12.FactoryLoadImage();
                    //default:    return Cmd0.FactoryLoadImage();
                }
            }
            else {
                VCard vcard = Cmd0.FactoryLoadImage();
                Nvm.Write("Shell", baShell);
                return vcard;
            }
        }
        catch(Exception e){ ;
            Log.d("VCard",  e.getMessage());
        }
        return null;
    }



    public static VCard ImportImage(String szJsonFilename) throws VirtualCardException {                  // erase old image and create new one from Json description.
        File   file;
        String szJson;
        JSONObject jsonCardImage;

        try {
            file = new File(szJsonFilename);
            Scanner scanner = new Scanner(file, "UTF-8");
            szJson = scanner.useDelimiter("\\A").next();
            jsonCardImage = new JSONObject(szJson);
            scanner.close();
        } catch (IOException e) {
            throw new VirtualCardException("Error opening file: " + szJsonFilename);
        }
        catch (JSONException e) {
            throw new VirtualCardException("Error parsing Json: " + szJsonFilename);
        }

        try {
            VCard newVcard;
            byte[] baShell = Base64.decode(jsonCardImage.getString("baShell"), Base64.DEFAULT);

            Shell shell = new Shell(baShell);
            switch (shell.getFvc()) {
                case 2:  newVcard = Cmd2.FactoryImportImage(jsonCardImage);  break;
                case 7:  newVcard = Cmd7.FactoryImportImage(jsonCardImage);  break;
                case 11: newVcard = Cmd11.FactoryImportImage(jsonCardImage); break;
                case 12: newVcard = Cmd12.FactoryImportImage(jsonCardImage); break;
                default: newVcard = Cmd0.FactoryImportImage(jsonCardImage);
            }

            Nvm.WipeDirectory();                                                                    // parsing went well so delete the old image
            newVcard.SaveImage();                                                                   // Now save the new one.

            newVcard.szTitle     = jsonCardImage.getString("szTitle");
            newVcard.szFilename = file.getName();
            return newVcard;
        }
        catch (JSONException e) {
            throw new VirtualCardException("Error parsing Json: " + szJsonFilename);
        }
    }


    public boolean ExportImage(String szJsonFilename) throws VirtualCardException {
        JSONObject jsonCardImage = ExportImage();
        String szCardImage = jsonCardImage.toString();
        File file = new File(szJsonFilename);
        try {
            file.createNewFile();
            FileWriter writer = new FileWriter(file);
            writer.write(szCardImage);
            writer.close();
            szSavedAsFilename = file.getName();
        } catch (IOException e) {
            throw new VirtualCardException("Error writing file: " + szJsonFilename);
        }

        return true;
    };


    public abstract void        SaveImage();                                                        // Save the CM image to the NVM store.
    public abstract JSONObject ExportImage();                                                       // Make a Json String of the CM Image
    public abstract void       Reset();                                                             // Called on Reset.
    public abstract byte[]     Select();                                                            // build the FCI's A5 contents.
    public abstract byte[]     Dispatch(byte[] baApdu);                                             // Process the incoming APDU

}
