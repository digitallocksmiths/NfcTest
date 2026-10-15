package com.digitallocksmiths.ItsoHce.VcardCmd11;

// ToDo: Consider this strategy....
//       Select: Copy NVM sectors to RAM.
//       Process: Work directly on RAM copies.
//       EndSession: If verified, copy RAM to NVM.
//       Combine sectors and MMMT is a mega structure.
//       Keep version A/B encrypted with Keys A/B
//       Key changes on every save.
//


import android.util.Log;

import com.digitallocksmiths.ItsoHce.Itso.Directory;
import com.digitallocksmiths.ItsoHce.VCard;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.Arrays;


public class Cmd11 extends VCard {
    private static final String TAG = "Cmd11";

    private static final byte  bCHAL_SIZE       =   8;                                              // Size of Random Challenge Data


    private static final short sPAGE_SIZE         = 256;                                            // size of sector (IPE or VRG records)
    private static class Sector   { byte[] baBody = new byte[sPAGE_SIZE]; }

    private static final byte  bPWD_SIZE        =   8;                                              // Size of Password Data
    private static class Password { byte[] baBody = new byte[bPWD_SIZE];  }



    // ==========================================================================
    // Clear on reset 'RAM' variables

    public byte[]  baChallenge          = new byte[bCHAL_SIZE];
    public byte[]  baChallengeTemp      = new byte[bCHAL_SIZE];
    public boolean fAuthenticated       = false;                                                    // Bool vars
    public boolean fPseudoAuthenticated = false;
    public short   sFciStart            = 0;                                                        // Short vars
    public short   sFciA5LenOffset      = 0;
    public short   sAllocated           = 0;

    // ==========================================================================
    // NV variables

    private byte[] baAid;
    private byte[] mAuthDesKeyA;
    private byte[] mAuthDesKeyB;
    private byte[] mAuthPseudoKeyA;
    private byte[] mAuthPseudoKeyB;
    //private byte[] baShell;
    private byte[] baPseudoShell;
    private byte[] baUID;
    private byte[] baPseudoUID;
    private byte[] baAuthKasParams;

    private byte[]       baCSS       = new byte[8];                                                 // Commit Confirmation Signature
    private int          iTsn;                                                                      // Transaction Sequence Number;

    // not needed? private Sector   Shell;                                                          //     0: Shell
    private Sector[]     aIpe;                                                                      // 1-E-1: Ipes      (0..E-2)
    private Sector[]     aVrg;                                                                      // 1-E-1: Vrgs      (1..E-2)
    private Sector       TTLog;                                                                     //     E: Log       (E-1)
    private Directory    directory;                                                                 //   E+1: Directory (E)
    private Password[]   aPassword;                                                                 // 1-E+1: Password  (0-E)



//  public static RandomData    Rng;                                                                // Shared Random generator.
//  public static Checksum      Crc;                                                                //        CRC resource.
//  public static Cipher        Cip;                                                                // 		  challenge processor/SK generator.
//  public static Signature     Sig;                                                                // 		  MAC verifyer/generator.
//  public static DESKey        SessionKey;                                                         //        ephemeral (transient) session key.
//  public static MessageDigest Hash;                                                               //		  Apdu Message digest.



    // ========================================
    // Constructor
    //
    // ========================================
    public Cmd11()  throws VCard.VirtualCardException {
        super();
        NameSet("CMD 11");

        int iE = shell.getE();

        aIpe = new Sector[iE-1];                                                                    // Allocate sectors according to the shell's E
        aVrg = new Sector[iE-1];                                                                    // ditto for VRGs
        for (int i=0; i< iE-1; i++) {                                                               // they are all sector sized
            aIpe[i] = new Sector();
            aVrg[i] = new Sector();
        }
        TTLog = new Sector();                                                                       // TT Log is also sector sized.
        aPassword       = new Password[iE+1];                                                       // Passwords are 1 per sector + 1 for TTLog & 1 for Directory
        for (int i = 0; i < aPassword.length; i++) {
            aPassword[i] = new Password();
        }

        // ToDo: Do we need to allocate the space.
        // Deserialize will create and assign byte[]s.
        // Just need to ensure JSON parser fills the correct size.
    }                                                                                               // Exit with all space allocated, to be populated later.


    // ========================================
    // ImageGetSize()
    //    Return the size of the serialized image in bytes.
    // ========================================
    protected int   ImageGetSize() {                                                                // subclasses indicate their own storage volume requirements
        Log.d(TAG, "ImageGetSize");
        // ToDo: Sizeof the image here.
        return  SerializeOverhead + baCSS.length +
                4   /* sizeof(iTsn) */  +
                SerializeOverhead + baAid.length +
                SerializeOverhead + mAuthDesKeyA.length +
                SerializeOverhead + mAuthDesKeyB.length +
                SerializeOverhead + mAuthPseudoKeyA.length +
                SerializeOverhead + mAuthPseudoKeyB.length +
                SerializeOverhead + baPseudoShell.length +
                SerializeOverhead + baUID.length +
                SerializeOverhead + baPseudoUID.length +
                SerializeOverhead + baAuthKasParams.length +
               (SerializeOverhead + sPAGE_SIZE)  * aIpe.length +
               (SerializeOverhead + sPAGE_SIZE)  * aVrg.length +
                SerializeOverhead + sPAGE_SIZE + /* TTLog */
                SerializeOverhead + directory.getLength() +
               (SerializeOverhead + bPWD_SIZE)   * aPassword.length;
    };

    // ========================================
    // ImageDeserialize()
    //      Make a new VCard from NVM store.
    // ========================================
    protected void  ImageDeserialize(ByteBuffer buffer) throws VirtualCardException {                                           // subclasses populate their working variables here.
        Log.d(TAG, "ImageDeserialize");
        // ToDo: Deserialize the image here.
        try {
            baCSS = VCard.DeserializeByteArray(buffer);
            iTsn = buffer.getInt();
            baAid = DeserializeByteArray(buffer);
            mAuthDesKeyA = DeserializeByteArray(buffer);
            mAuthDesKeyB = DeserializeByteArray(buffer);
            mAuthPseudoKeyA = DeserializeByteArray(buffer);
            mAuthPseudoKeyB = DeserializeByteArray(buffer);
            baPseudoShell = DeserializeByteArray(buffer);
            baUID = DeserializeByteArray(buffer);
            baPseudoUID = DeserializeByteArray(buffer);
            baAuthKasParams = DeserializeByteArray(buffer);
            for (Sector sector : aIpe) {
                sector.baBody = DeserializeByteArray(buffer);
            }
            for (Sector sector : aVrg) {
                sector.baBody = DeserializeByteArray(buffer);
            }
            TTLog.baBody = DeserializeByteArray(buffer);
            directory = new Directory(shell, DeserializeByteArray(buffer));
            for (Password password : aPassword) {
                password.baBody = DeserializeByteArray(buffer);
            }
        }
        catch (VirtualCardException e) {
            Log.d(TAG, "Corrupt Image file");
            throw e;
        }
    }

    // ========================================
    // ImageSerialize()
    //      Add this class's image variables
    //      to the buffer.
    // ========================================
    protected void  ImageSerialize(ByteBuffer buffer) {                                             // subclasses serialize their variables here.
        Log.d(TAG, "ImageSerialize");
        VCard.SerializeByteArray(buffer, baCSS);
        buffer.putInt(iTsn);
        SerializeByteArray(buffer, baAid);
        SerializeByteArray(buffer, mAuthDesKeyA);
        SerializeByteArray(buffer, mAuthDesKeyB);
        SerializeByteArray(buffer, mAuthPseudoKeyA);
        SerializeByteArray(buffer, mAuthPseudoKeyB);
        SerializeByteArray(buffer, baPseudoShell);
        SerializeByteArray(buffer, baUID);
        SerializeByteArray(buffer, baPseudoUID);
        SerializeByteArray(buffer, baAuthKasParams);
        for (Sector sector : aIpe)            { SerializeByteArray( buffer, sector.baBody);   }
        for (Sector sector : aVrg)            { SerializeByteArray( buffer, sector.baBody);   }
        SerializeByteArray( buffer, TTLog.baBody);
        SerializeByteArray( buffer, directory.Get());
        for (Password password : aPassword)   { SerializeByteArray(buffer,  password.baBody); }
    }

    // ========================================
    // JsonParse(JSONObject szJsonCardImage)
    //      Make a new VCard from the JSON image.
    // ========================================
    protected void  JsonParse(JSONObject jsonCardImage) throws JSONException, VirtualCardException {  // parse the JSON image into the CM Image
        Log.d(TAG, "JsonParse");

        // shell was read and parsed by the caller.

        iTsn    = 0;                                                                                // new image so start the transaction counter form zero
        Arrays.fill(baCSS, (byte)0);                                                                // And clear the CSS

        baAid           = DecodeJsonByteArray(jsonCardImage, "baAid");
        mAuthDesKeyA    = DecodeJsonByteArray(jsonCardImage, "mAuthDesKeyA");
        mAuthDesKeyB    = DecodeJsonByteArray(jsonCardImage, "mAuthDesKeyB");
        mAuthPseudoKeyA = DecodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyA");
        mAuthPseudoKeyB = DecodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyB");
        baPseudoShell   = DecodeJsonByteArray(jsonCardImage, "baPseudoShell");
        baUID           = DecodeJsonByteArray(jsonCardImage, "baUID");
        baPseudoUID     = DecodeJsonByteArray(jsonCardImage, "baPseudoUID");
        baAuthKasParams = DecodeJsonByteArray(jsonCardImage, "baAuthKasParams");

        int iSector = 1;
        JSONArray ipeList = jsonCardImage.getJSONArray("baIpeList");                          // Ipes and Vrgs into sectors
        for (int i = 0; i < ipeList.length(); i++) {                                                // should be E-1 of them.
            JSONObject ipe;
            try                     { ipe = ipeList.getJSONObject(i); }
            catch (JSONException e) { ipe = null;                     }
            if (ipe != null && ipe.length() == 2) {
                setIpe(iSector, DecodeJsonByteArray(ipe, "baIpe"));
                setVrg(iSector, DecodeJsonByteArray(ipe, "baVrg"));
            }
            iSector++;
        }

        setLog(DecodeJsonByteArray(jsonCardImage, "baLog"));                                  // Log into a sector
        directory       = new Directory(shell, DecodeJsonByteArray(jsonCardImage, "baDir"));  // Dir into a sector

        JSONArray pwdList = jsonCardImage.getJSONArray("PasswordList");                       // Passwords into sectors
        for (int i = 0; i < pwdList.length(); i++) {                                                // should be E of them.
            setPwd(i, DecodeStringToByteArray(pwdList.getString(i)));
        }
        // If we are successful the caller will erase the old image and then call SaveImage().
        //
    }


    // ========================================
    // JsonExport()
    //      Save the CM image to the NVM store.
    // ========================================
    protected void  JsonExport(JSONObject jsonCardImage) throws JSONException {                     // Add data to the JSON object.
        Log.d(TAG, "JsonExport");

        EncodeJsonByteArray(jsonCardImage, "baAid",           baAid);
        EncodeJsonByteArray(jsonCardImage, "mAuthDesKeyA",    mAuthDesKeyA);
        EncodeJsonByteArray(jsonCardImage, "mAuthDesKeyB",    mAuthDesKeyB);
        EncodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyA", mAuthPseudoKeyA);
        EncodeJsonByteArray(jsonCardImage, "mAuthPseudoKeyB", mAuthPseudoKeyB);
        EncodeJsonByteArray(jsonCardImage, "baPseudoShell",   baPseudoShell);
        EncodeJsonByteArray(jsonCardImage, "baUID",          baUID );
        EncodeJsonByteArray(jsonCardImage, "baPseudoUID",     baPseudoUID);
        EncodeJsonByteArray(jsonCardImage, "baAuthKasParams", baAuthKasParams);
        EncodeJsonByteArray(jsonCardImage, "baDir",           directory.Get());
        EncodeJsonByteArray(jsonCardImage, "baLog",           TTLog.baBody);
        JSONArray ipeList = new JSONArray();
        for (int i = 1; i < shell.getE(); i++) {
            if (directory.IsEntryValid(i)) {
                JSONObject ipe = new JSONObject();
                EncodeJsonByteArray(ipe, "baIpe", getIpe(i));
                EncodeJsonByteArray(ipe, "baVrg", getVrg(i));
                ipeList.put(ipe);
            }
            else {
                ipeList.put(JSONObject.NULL);
            }
        }
        jsonCardImage.put("baIpeList", ipeList);
        JSONArray pwdList = new JSONArray();
        for (Password password : aPassword) {
            pwdList.put(EncodeByteArrayToString(password.baBody));
        }
        jsonCardImage.put("PasswordList", pwdList);
    }


    // ========================================
    // Reset()
    //      clear/init working variables.
    //      return the FCI
    // ========================================
    public void Reset() throws VirtualCardException {                                               // Card reset
        Log.d(TAG, "Reset");
        // ToDo: Clear CM Ram vars here. Maybe read the image?

        Arrays.fill(baChallenge,     (byte)0);
        Arrays.fill(baChallengeTemp, (byte)0);
        fAuthenticated       = false;
        fPseudoAuthenticated = false;
        sFciStart            = 0;
        sFciA5LenOffset      = 0;
        sAllocated           = 0;

    }

    // ========================================
    // Select()
    //      construct and return the FCI
    // ========================================
    public byte[] Select() {                                                                        // Card select
        Log.d(TAG, "Select");                                                                       // Build FCI.A5's contents
        try {
            Reset();                                                                                // Clear on reset//select variables initialized.
        }
        catch (VirtualCardException e) {
            Log.d(TAG, "Select: + " + e.getMessage() );
            return new byte[] { (byte)0x80, 1, 11};
        }

        // ToDo: Build the FCI A5 contents here
        return new byte[] { (byte)0x80, 1, 11};
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


// ==========================================================================================
// Because a phon keeps this in RAM and writes it to the file at the same time as the sectors
// there is no need to juggle the free page mechanism.
// Pages can be written directly at their own index.
//
// Similarly, data integrity is part and parcel of the image preservation/recovery in
// the VCard class. No need for the MMMT crc field either.
//
// So, Sector count = 3 + (2*E-1)
//     Shell    = sector 0              // index since shell sector is omitted
//     Ipe/Vrg  = sector 1-E-1          // 0..E-2
//     Log      = sector E              // E-1
//     Dir      = sector E+1            // E
// ==========================================================================================

    private  void arrayCopy(byte[] baSrc, byte[] baDst) {       // Local Array copy utility
        System.arraycopy(baSrc, 0, baDst, 0, Math.min(baSrc.length, baDst.length));
    }

    private  byte[] makeSector(byte[] baV) {
        if (baV.length == sPAGE_SIZE) return baV;
        else return Arrays.copyOf(baV, sPAGE_SIZE);
    }


    public void   setCCS(byte[] baV)                  { arrayCopy(baV, baCSS);                  }   // CCS accessors
    public void   getCCS(byte[] baV)                  { arrayCopy(baCSS, baV);                  }
    public byte[] getCCS()                            { return baCSS;                           }
    public void   setTsn(int i)                       { iTsn = i;                               }  // iTsn accessors
    public int    getTsn()                            { return iTsn;                            }
    public void   incTsn()                            { iTsn++;                                 }

    public void   setDir(byte[] baV)              { directory.Set(baV);                         }   // Dir accessors
    public void   getDir(byte[] baV)              { arrayCopy(directory.Get(), baV);            }
    public byte[] getDir()                        { return directory.Get();                     }
    public void   setLog(byte[] baV)              { TTLog.baBody = makeSector(baV);             }  // Log accessors
    public void   getLog(byte[] baV)              { arrayCopy(TTLog.baBody, baV);               }
    public byte[] getLog()                        { return TTLog.baBody;                        }
    public void   setIpe(int iIndex, byte[] baV)  { aIpe[iIndex-1].baBody = makeSector(baV);    }  // Ipe  accessors
    public void   getIpe(int iIndex, byte[] baV)  { arrayCopy(aIpe[iIndex-1].baBody, baV);      }
    public byte[] getIpe(int iIndex)              { return aIpe[iIndex-1].baBody;               }
    public void   setVrg(int iIndex, byte[] baV)  { aVrg[iIndex-1].baBody = makeSector(baV);    }  // VrgA accessors
    public void   getVrg(int iIndex, byte[] baV)  { arrayCopy(aVrg[iIndex-1].baBody, baV);      }
    public byte[] getVrg(int iIndex)              { return aVrg[iIndex-1].baBody;               }
    public void   setPwd(int i, byte[] baV)       { aPassword[i].baBody = baV;                  }


    // ToDo: do we want to provide password accessors here to mask the array/sector displacement from the caller?




}