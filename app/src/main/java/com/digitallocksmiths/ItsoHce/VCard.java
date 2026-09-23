package com.digitallocksmiths.ItsoHce;

import android.os.Build;

import androidx.annotation.RequiresApi;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Scanner;

public abstract class VCard {

    public static class VirtualCardException extends Exception {

        public VirtualCardException(String szMsg) {
            super(szMsg);
        }
    }


    public static VCard Factory(String szFilename) throws VirtualCardException {
        String szJson = "";
        //try {
            //File file = new File(szFilename);
            //Scanner scanner = new Scanner(file, "UTF-8");
            //szJson = scanner.useDelimiter("\\A").next();
            //scanner.close();
        //} catch (IOException e) {
        //    throw new VirtualCardException("Error opening file: " + szFilename);
        //}

        // szJson now contains the JSON string
        return VcardCmd2.Factory(szFilename);
        //return null;
    }


    public boolean SaveImage(String szFilename) throws VirtualCardException {
        String szBody = CreateImage();

        File file = new File(szFilename);
        try {
            file.createNewFile();
            FileWriter writer = new FileWriter(file);
            writer.write(String.valueOf(szBody));
            writer.close();
        } catch (IOException e) {
            throw new VirtualCardException("Error writing file: " + szFilename);
        }

        return true;
    };


    public abstract String CreateImage();




}
