package com.digitallocksmiths.ItsoHce;

import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

// NvmFile.java
// save and recover byte[] from file system.
// This provides Non-Volatile storage capabilities for the emulated media.
//
// Emulating storage as file per sector ensures there is no collateral damage
// from a single failed update.
//
// ToDo:
//      This class should also encrypt and decrypt the data.
//


public class Nvm {
    String TAG = "Nvm";

    String szImageDir;
    // private Key Key;

    public Nvm(String szImageDir /* key here */) {                                              // Constructor
        this.szImageDir = szImageDir.endsWith(File.separator) ? szImageDir : szImageDir + File.separator;

        File dir = new File(szImageDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        // this.Key = Key;
    }

    public void Write(String szFilename, byte[] baFileContents) throws Exception {                   // Save to file
        Log.d(TAG, "Write: " + szFilename);

        byte[] data = (baFileContents != null) ? baFileContents : new byte[0];
        String base64Str = Base64.encodeToString(data, Base64.NO_WRAP);

        File file = new File(szImageDir + szFilename);
        try {
            file.createNewFile();
            FileWriter writer = new FileWriter(file);
            writer.write(base64Str);
            writer.close();
        } catch (IOException e) {
            throw new VCard.VirtualCardException("Error writing file: " + szFilename);
        }

    }

    public byte[] Read(String szFilename)  {                                                        // Load from file
        Log.d(TAG, "Read: " + szFilename);

        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(szImageDir + szFilename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return Base64.decode(sb.toString(), Base64.DEFAULT);
        }
        catch (Exception e) {                                                                       // if it fails we get null
            return null;
        }
    }

    public void WipeDirectory() {
        File dir = new File(szImageDir);
        for (File file : dir.listFiles()) {
            file.delete();
        }
    }


}
