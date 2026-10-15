package com.digitallocksmiths.ItsoHce.VcardCmd11;

// Media memory management table

import android.util.Log;

import com.digitallocksmiths.ItsoHce.Nvm;
import com.digitallocksmiths.ItsoHce.VCard;

import java.nio.ByteBuffer;
import java.util.Arrays;

// ==========================================================================================
// Because we keep this in RAM and write it to the file at the same time as the sectors
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


public class Mmmt {
    private static final String TAG = "Mmmt";


    private static final short sPAGE_SIZE         = 256;                        // size of sector (IPE or VRG records)
    private static class Sector   { byte[] baBody = new byte[sPAGE_SIZE]; }

    public static final short sMAXIPE_SIZE 		  = 228; 			            // 16 byte footer and 8 byte password on top of this must be < 256.

    public static final short sSHELL_maxE 		  = 16;				            // Limit for Geometry E
    public static final short sFREE_PAGE_COUNT    = 8; 				            // Number of vacant pages for IPE updates.

    // ================================================================
    private int     iE;                                                         // Shell.E from the constructor

    // remembered in file
    private byte[]       baCSS       = new byte[8];                             // Commit Confirmation Signature
    private int          iTsn;                                                  // Transaction Sequence Number;

    // not needed? private Sector   Shell;                                      //     0: Shell
    private Sector[]    aIpe;                                                   // 1-E-1: Ipes (1..E-1)
    private Sector[]    aVrg;                                                   // 1-E-1: Vrgs (1..E-1)


    public Mmmt(int E) {
        iE = E;
        aIpe = new Sector[E+1];
        for (int i=0; i< E+1; i++) {
            aIpe[i] = new Sector();
        }
        aVrg = new Sector[E-1];
        for (int i=0; i< E-1; i++) {
            aVrg[i] = new Sector();
        }
    }

/*
    public void Erase() {

        Arrays.fill(baCSS,       (byte)0);
        iTsn = 0;
        bDir = 0;
        bLog = 0;
        Arrays.fill(baEListIpe,  (byte)0);
        Arrays.fill(baEListVrg,  (byte)0);
    }
*/


    private  void arrayCopy(byte[] baSrc, byte[] baDst) {       // Local Array copy utility
        System.arraycopy(baSrc, 0, baDst, 0, Math.min(baSrc.length, baDst.length));
    }

    public void   setCCS(byte[] baV)                  { arrayCopy(baV, baCSS);                  }   // CCS accessors
    public void   getCCS(byte[] baV)                  { arrayCopy(baCSS, baV);                  }
    public byte[] getCCS()                            { return baCSS;                           }
    public void   setTsn(int i)                       { iTsn = i;                               }  // iTsn accessors
    public int    getTsn()                            { return iTsn;                            }
    public void   incTsn()                            { iTsn++;                                 }
    public void   setDirPage(byte[] baV)              { arrayCopy(baV, aIpe[iE].baBody);      }   // Dir accessors
    public void   getDirPage(byte[] baV)              { arrayCopy(aIpe[iE].baBody, baV);        }
    public byte[] getDirPage()                        { return aIpe[iE].baBody;                 }
    public void   setLogPage(byte[] baV)              { arrayCopy(baV, aIpe[iE-1].baBody);      }   // Log accessors
    public void   getLogPage(byte[] baV)              { arrayCopy(aIpe[iE-1].baBody, baV);      }
    public byte[] getLogPage()                        { return aIpe[iE-1].baBody;               }
    public void   setIpePage(int iIndex, byte[] baV)  { arrayCopy(baV, aIpe[iIndex-1].baBody);  }   // Ipe  accessors
    public void   getIpePage(int iIndex, byte[] baV)  { arrayCopy(aIpe[iIndex-1].baBody, baV);  }
    public byte[] getIpePage(int iIndex)              { return aIpe[iIndex-1].baBody;           }
    public void   setVrgPage(int iIndex, byte[] baV)  { arrayCopy(baV, aVrg[iIndex-1].baBody);  }   // VrgA accessors
    public void   getVrgPage(int iIndex, byte[] baV)  { arrayCopy(aVrg[iIndex-1].baBody, baV);  }
    public byte[] getVrgPage(int iIndex)              { return aVrg[iIndex-1].baBody;           }


    protected int   ImageGetSize() {                                                                // indicate our storage volume requirements
        Log.d(TAG, "ImageGetSize");
        return  VCard.SerializeOverhead + baCSS.length +
                4 + /* sizeof(iTsn) */
                (iE + 1) * (VCard.SerializeOverhead + sPAGE_SIZE) +
                (iE - 1) * (VCard.SerializeOverhead + sPAGE_SIZE);
    };


    // ========================================
    // Deserialize()
    //      Fill from buffer.
    // ========================================
    protected void  ImageDeserialize(ByteBuffer buffer) {                                           // subclasses populate their working variables here.
        Log.d(TAG, "ImageDeserialize");

        baCSS           = VCard.DeserializeByteArray(buffer);
        iTsn            = buffer.getInt();
        for (int i=0; i< iE+1; i++) {
            aIpe[i].baBody = VCard.DeserializeByteArray(buffer);
        }
        for (int i=0; i< iE-1; i++) {
            aVrg[i].baBody =  VCard.DeserializeByteArray(buffer);
        }
    }

    // ========================================
    // ImageSerialize()
    //      Fill the buffer
    // ========================================
    protected void  ImageSerialize(ByteBuffer buffer) {                                             // subclasses serialize their variables here.
        Log.d(TAG, "ImageSerialize");

        VCard.SerializeByteArray(buffer, baCSS);
        buffer.putInt(iTsn);
        for (int i=0; i< iE+1; i++) {
            VCard.SerializeByteArray(buffer, aIpe[i].baBody);
        }
        for (int i=0; i< iE-1; i++) {
            VCard.SerializeByteArray(buffer, aVrg[i].baBody);
        }
    }


}
