package com.digitallocksmiths.ItsoHce.VcardCmd11;

// Media memory management table

import com.digitallocksmiths.ItsoHce.NvmFile;

import java.nio.ByteBuffer;
import java.util.Arrays;


public class Mmmt {

    public static final short sPAGE_SIZE 		= 256; 				// used for IPEs / VRGs / Logs....
    public static final short sMAXIPE_SIZE 		= 228; 				// 16 byte footer and 8 byte password on top of this must be < 256.

    public static final short sSHELL_maxE 		= 16;				// Limit for Geometry E
    public static final short sFREE_PAGE_COUNT  = 8; 				// Number of vacant pages for IPE updates.

    public byte[]       baCSS       = new byte[8];                  // Commit Confirmation Signature
    public int          iTsn;                                       // Transaction Sequence Number;
    public byte         bDir;                                       // Current Directory
    public byte         bLog;                                       // Current Log file
    public byte[]       baEListIpe  = new byte[sSHELL_maxE-1];      // sectors used by Directory E entries IPE. // E[1..Shell.E-1]
    public byte[]       baEListVrg  = new byte[sSHELL_maxE-1];      // sectors used by Directory E entries VRG.
    public byte[]       baFreePages = new byte[sFREE_PAGE_COUNT];   // sectors unused
    public byte[]       baCrc       = new byte[4];                  // checksum of the above.


    public Mmmt() {

    }

    private  void arrayCopy(byte[] baSrc, int iSrcOff, byte[] baDst, int iDstOff, int iLen) {       // Local Array copy utility
        System.arraycopy(baSrc, iSrcOff, baDst, iDstOff, iLen);
    }

    public void setCCS(byte[] baV, int iOff)   { arrayCopy(baV, iOff, baCSS, 0, baCSS.length); }	// CCS accessors
    public void getCCS(byte[] baV, short sOff) { arrayCopy(baCSS, 0, baV, sOff, baCSS.length); }

    public int  getTsn()                              { return iTsn;                }               // iTsn accessors
    public void setTsn(int i)                         { iTsn = i;                   }
    public void incTsn()                              { this.iTsn++;                }

    public void setDirPage(byte bPage)                { bDir = bPage;	            }   		    // Dir accessors
    public byte getDirPage()                          { return bDir;                }

    public void setLogPage(byte bPage)                { bLog = bPage;	            } 				// Log accessors
    public byte getLogPage()                          { return bLog;                }

    public void setIpePage(short sIndex, byte bPage)  {	baEListIpe[sIndex] = bPage;	}				// Ipe  accessors
    public byte getIpePage(short sIndex)              { return baEListIpe[sIndex];  }

    public void setVrgPage(short sIndex, byte bPage)  {	baEListVrg[sIndex] = bPage;	}				// VrgA accessors
    public byte getVrgPage(short sIndex)              { return baEListVrg[sIndex];  }

    public void setFreePage(short sIndex, byte bPage) {	baFreePages[sIndex] = bPage; }				// Free Page accessors
    public byte getFreePage(short sIndex)             { return baFreePages[sIndex];  }


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

    public void setCrc() {                                      // Set the structure's CRC
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

    public void Save(NvmFile nvm, String szFilename) {
        try {
            nvm.Write(szFilename, toByteArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void Load(NvmFile nvm, String szFilename) {
        try {
            byte[] data = nvm.Read(szFilename);
            fromByteArray(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
