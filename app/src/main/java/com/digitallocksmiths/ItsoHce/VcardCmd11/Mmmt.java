package com.digitallocksmiths.ItsoHce.VcardCmd11;

// Media memory management table

import com.digitallocksmiths.ItsoHce.Nvm;

import java.nio.ByteBuffer;
import java.util.Arrays;


public class Mmmt {

    public static final short sPAGE_SIZE 		= 256; 				// used for IPEs / VRGs / Logs....
    public static final short sMAXIPE_SIZE 		= 228; 				// 16 byte footer and 8 byte password on top of this must be < 256.

    public static final short sSHELL_maxE 		= 16;				// Limit for Geometry E
    public static final short sFREE_PAGE_COUNT  = 8; 				// Number of vacant pages for IPE updates.


    private Nvm     nvm;
    private String  szOwnFilename;                                  // read from this
    private String  szTwinFilename;                                 // write to this

    // ================================================================
    // remembered in file
    private byte[]       baCSS       = new byte[8];                  // Commit Confirmation Signature
    private int          iTsn;                                       // Transaction Sequence Number;
    private byte         bDir;                                       // Current Directory
    private byte         bLog;                                       // Current Log file
    private byte[]       baEListIpe  = new byte[sSHELL_maxE-1];      // sectors used by Directory E entries IPE. // E[1..Shell.E-1]
    private byte[]       baEListVrg  = new byte[sSHELL_maxE-1];      // sectors used by Directory E entries VRG.
    private byte[]       baFreePages = new byte[sFREE_PAGE_COUNT];   // sectors unused
    private byte[]       baCrc       = new byte[4];                  // checksum of the above.


    public Mmmt(Nvm nvm, String szOwnFilename, String szTwinFilename) {
       this.nvm = nvm;                                                                              // file store
       this.szOwnFilename  = szOwnFilename;                                                         // read from this
       this.szTwinFilename = szTwinFilename;                                                        // write to this
    }

    public void Erase() {
        Arrays.fill(baCSS,       (byte)0);
        iTsn = 0;
        bDir = 0;
        bLog = 0;
        Arrays.fill(baEListIpe,  (byte)0);
        Arrays.fill(baEListVrg,  (byte)0);
        Arrays.fill(baFreePages, (byte)0);
        Arrays.fill(baCrc, (byte)0);
    }

    private  void arrayCopy(byte[] baSrc, int iSrcOff, byte[] baDst, int iDstOff, int iLen) {       // Local Array copy utility
        System.arraycopy(baSrc, iSrcOff, baDst, iDstOff, iLen);
    }

    public void setCCS(byte[] baV, int iOff)   { arrayCopy(baV, iOff, baCSS, 0, baCSS.length); }	// CCS accessors
    public void getCCS(byte[] baV, short sOff) { arrayCopy(baCSS, 0, baV, sOff, baCSS.length); }

    public int  getTsn()                              { return iTsn;                }               // iTsn accessors
    //public void setTsn(int i)                         { iTsn = i;                   }
    //public void incTsn()                              { this.iTsn++;                }

    public void setDirPage(byte bPage)                { bDir = bPage;	            }   		    // Dir accessors
    public byte getDirPage()                          { return bDir;                }

    public void setLogPage(byte bPage)                { bLog = bPage;	            } 				// Log accessors
    public byte getLogPage()                          { return bLog;                }

    public void setIpePage(int iIndex, byte bPage)    {	baEListIpe[iIndex] = bPage;	}				// Ipe  accessors
    public byte getIpePage(int iIndex)                { return baEListIpe[iIndex];  }

    public void setVrgPage(int iIndex, byte bPage)    {	baEListVrg[iIndex] = bPage;	}				// VrgA accessors
    public byte getVrgPage(int iIndex)                { return baEListVrg[iIndex];  }

    public void setFreePage(int iIndex, byte bPage)   {	baFreePages[iIndex] = bPage; }				// Free Page accessors
    public byte getFreePage(int iIndex)               { return baFreePages[iIndex];  }


    // ==========================================================================================   // CRC management
    // CRC functions.

    private void UpdateCrc(byte[] baSum, byte b) {
        baSum[0] += (b & 0xFF);
        baSum[1] += baSum[0];
        baSum[2] += baSum[1];
        baSum[3] += baSum[2];
    }

    private void CalculateStructureCrc(byte[] baSum) {
        baSum[0] = (byte)0xff;
        baSum[1] = 0x00;
        baSum[2] = (byte)0xff;
        baSum[3] = 0x00;

        int i;
        for (i = 0; i < baCSS.length;       i++) { UpdateCrc(baSum, baCSS[i]); }
        UpdateCrc(baSum, (byte)iTsn);
        UpdateCrc(baSum, (byte)(iTsn >> 8));
        UpdateCrc(baSum, (byte)(iTsn >> 16));
        UpdateCrc(baSum, (byte)(iTsn >> 24));
        UpdateCrc(baSum, bDir);
        UpdateCrc(baSum, bLog);
        for (i = 0; i < baEListIpe.length;  i++) { UpdateCrc(baSum, baEListIpe[i]); }
        for (i = 0; i < baEListVrg.length;  i++) { UpdateCrc(baSum, baEListVrg[i]); }
        for (i = 0; i < baFreePages.length; i++) { UpdateCrc(baSum, baFreePages[i]); }
    }

    private  void setCrc() {                                      // Set the structure's CRC
        CalculateStructureCrc(baCrc);
    }

    public boolean checkCrc() {                                 // Verify the structure's CRC
        byte[] baSum = new byte[4];
        CalculateStructureCrc(baSum);
        return Arrays.equals(baCrc, baSum);
    }

    // ==========================================================================================
    // To byte[] and from byte[].

    public byte[] toByteArray() {
        int totalLen = baCSS.length + 4 + 1 + 1 + baEListIpe.length + baEListVrg.length + baFreePages.length + baCrc.length;
        ByteBuffer buffer = ByteBuffer.allocate(totalLen);
        buffer.put(baCSS);
        buffer.putInt(iTsn);
        buffer.put(bDir);
        buffer.put(bLog);
        buffer.put(baEListIpe);
        buffer.put(baEListVrg);
        buffer.put(baFreePages);
        buffer.put(baCrc);
        return buffer.array();
    }

    public void fromByteArray(byte[] baBlob) {
        if (baBlob == null) return;
        ByteBuffer buffer = ByteBuffer.wrap(baBlob);
        if (buffer.remaining() >= baCSS.length)       { buffer.get(baCSS);       }
        if (buffer.remaining() >= 4)                  { iTsn = buffer.getInt();  }
        if (buffer.remaining() >= 1)                  { bDir = buffer.get();     }
        if (buffer.remaining() >= 1)                  { bLog = buffer.get();     }
        if (buffer.remaining() >= baEListIpe.length)  { buffer.get(baEListIpe);  }
        if (buffer.remaining() >= baEListVrg.length)  { buffer.get(baEListVrg);  }
        if (buffer.remaining() >= baFreePages.length) { buffer.get(baFreePages); }
        if (buffer.remaining() >= baCrc.length)       { buffer.get(baCrc);       }
    }

    // ==========================================================================================
    // Save and Load.

    public void Save() {
        try {
            this.iTsn++;                                                                            // we've aged by 1
            setCrc();                                                                               // update the CRC
            nvm.Write(szTwinFilename, toByteArray());                                               // Write over our twin.
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void Load() {
        try {
            byte[] data = nvm.Read(szOwnFilename);
            fromByteArray(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
