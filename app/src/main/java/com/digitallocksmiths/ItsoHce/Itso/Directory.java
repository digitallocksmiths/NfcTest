package com.digitallocksmiths.ItsoHce.Itso;

import java.util.Arrays;

public class Directory {

    private final int    iE;
    private final int    iSctl;
    private final byte[] baDirectory;

    public Directory(int iE, int iSctl, byte[] baDirectory) {
        this.iE          = iE;
        this.iSctl       = iSctl;
        this.baDirectory = baDirectory;
    }

    public int getLength()         { return baDirectory.length; }
    public byte[] getDirectory()   { return baDirectory; }

    public byte[] getEntry(int i) {
        int iOffset = 2 + (i-1)* 5;
        return Arrays.copyOfRange(baDirectory, iOffset, iOffset+5);
    }

    public boolean IsEntryValid(int i) {
        if (i < 1 || i > iE)                                                { return false; }
        int iOffset = 2 + (i - 1) * 5;
        for (int j = 0; j < 5; j++) { if (baDirectory[iOffset + j] != 0x00) { return true;  } }     // An entry is considered valid if it is NOT all zeros
        return false;
    }

}
