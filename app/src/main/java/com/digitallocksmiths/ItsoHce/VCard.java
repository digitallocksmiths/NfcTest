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

    public static class VirtualCardException extends Exception {
        public VirtualCardException(String szMsg) {
            super(szMsg);
        }
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
    public abstract byte[]     Reset();



}
