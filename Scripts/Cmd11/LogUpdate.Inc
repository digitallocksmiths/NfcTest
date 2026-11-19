// LogUpdate.Inc
//
//  Include file (not a test). Sends Update Log (901C) with record Rec (Len
//  bytes, 1..30), adds the exchange to the session hash, checks it is
//  accepted, and updates Model, the expected contents of the 5 records
//  Read Log returns (5 x 30 bytes, newest first):
//
//      new record #1 = Rec, padded with 00 up to 30 bytes
//                      (none of the previous record's data may remain)
//      records #2..5 = old records #1..4 (old #5 drops out)
//
//  The including script must declare beforehand:
//      SW_OK, HashAcc, Tx, Rx, LogPwd, Rec, Len (u8), Model, Mark (u8, used in the messages),
//      Zeros (30 bytes of 00)
//

Tx = 901C 0000 ((u8)(LogPwd.Length + Rec.Length)) LogPwd Rec;
Rx = @ReaderA.Apdu("Update Log, mark " :: Mark :: ", length " :: Len, Tx);  HashAcc = @Sha256.Update(HashAcc, Tx);  HashAcc = @Sha256.Update(HashAcc, Rx);
@Test(Rx[¬1..] == SW_OK, "Update Log accepted, mark " :: Mark :: ", length " :: Len);

if (Len < 30) {
    Model = Rec Zeros[Len..2F] Model[0..BF];
}
else {
    Model = Rec Model[0..BF];
}
