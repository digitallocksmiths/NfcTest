package com.digitallocksmiths.ItsoHce.Itso;

import java.util.Arrays;

public class Shell {

    private byte[] baShell;

    public Shell(byte[] baShell) {
        this.baShell = baShell;
    }

    public byte getLength()         { return (byte)(  baShell[0] & 0xFC); }
    public byte getBitmap()         { return (byte)(((baShell[0] & 0x03) << 4) | ( (baShell[1] & 0xF0) >> 4)); }
    public byte getFormatRevision() { return (byte)(  baShell[1] & 0x0F); }
    public byte[] getIsrn()         { return Arrays.copyOfRange(baShell, 2, 9); }
    public byte[] getIin()          { return Arrays.copyOfRange(baShell, 2, 3); }
    public byte[] getOid()          { return Arrays.copyOfRange(baShell, 5, 2); }
    public byte[] getIssnChd()      { return Arrays.copyOfRange(baShell, 7, 4); }
    public byte getFvc()            { return baShell[11]; }
    public byte getKsc()            { return baShell[12]; }
    public byte  getKvc()           { return baShell[13]; }
    public short getDate()          { return (short)((baShell[14]<<8) | baShell[15]); }
    public byte getB()              { return baShell[16]; }
    public byte getS()              { return baShell[17]; }
    public byte getE()              { return baShell[18]; }
    public byte getSctl()           { return baShell[19]; }
    // ignoring padding and MCRN!
    public short getSecrec()        { return (short)((baShell[getLength()-2]<<8) | baShell[getLength()-1]); }


}
