// DirProbe.Inc
//
//  Include file (not a test). Shows which directory the card is using for
//  slot IpeNo by reading IPE #IpeNo (9012), and checks it against ExpDir:
//      entry IpeNo of ExpDir all 00 -> Read Ipe must give 6A83 (no record)
//      otherwise                    -> Read Ipe must give 9000, and the
//                                      first 5 bytes must be that entry.
//  The exchange is added to the session hash.
//
//  The including script must declare beforehand:
//      SW_OK, SW_NOREC, HashAcc, Tx, Rx, IpeNo (u8), Off (u8, offset of
//      entry IpeNo), ExpDir, Entry, Step (u8, used in the messages)
//

Entry = ExpDir[Off..(Off+4)];
Tx = 9012 IpeNo 00 00;
Rx = @ReaderA.Apdu("Read Ipe #" :: IpeNo :: " (probe " :: Step :: ")", Tx);  HashAcc = @Sha256.Update(HashAcc, Tx);  HashAcc = @Sha256.Update(HashAcc, Rx);
if (Entry == 0000000000) {
    @Test(Rx[¬1..] == SW_NOREC, "Directory " :: Step :: " in use: slot #" :: IpeNo :: " empty (6A83)");
}
else {
    @Test(Rx[¬1..] == SW_OK, "Directory " :: Step :: " in use: slot #" :: IpeNo :: " occupied (9000)");
    @Test(Rx[0..4] == Entry, "Directory " :: Step :: " in use: slot #" :: IpeNo :: " entry as written");
}
