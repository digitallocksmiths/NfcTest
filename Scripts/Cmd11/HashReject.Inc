// HashReject.Inc
//
//  Include file (not a test). The script has run a session (an IPE update
//  with Mark, plus whatever else) and built HashAcc so that it does NOT
//  match the card's session hash. This has the ISAM sign that hash, sends
//  a well formed End Session with the signature, and checks:
//      - End Session is rejected: 6300 (MAC mismatch);
//      - the session is over: Update Ipe now gives 6982;
//      - the update is discarded: before a reset (not authenticated, seal
//        redacted) and after one, slot IpeNo reads as Committed.
//
//  The including script must declare beforehand:
//      everything Authenticate.Inc and SessionSig.Inc need, SW_OK, SW_AUTH,
//      SW_SEC, Tx, Rx, Pwd, IpeNo, Ipe, Committed, Redacted, Case (u8)
//

@Include ("SessionSig.Inc");
Rx = @ReaderA.Apdu("End Session (hash case " :: Case :: ")", 9020 0000 08 Sig 00);
@Test(Rx[¬1..] == SW_AUTH, "Case " :: Case :: ": End Session rejected, the hashes differ");

Tx = 9018 IpeNo 00 ((u8)(Pwd.Length + Ipe.Length)) Pwd Ipe;
Rx = @ReaderA.Apdu("Update Ipe (after the rejection)", Tx);
@Test(Rx[¬1..] == SW_SEC, "Case " :: Case :: ": the session is over");

Rx = @ReaderA.Apdu("Read Ipe #" :: IpeNo :: " (not authenticated)", 9012 IpeNo 00 00);
@Test(Rx[5..¬2] == Committed[..¬16_d] Redacted, "Case " :: Case :: ": update discarded at once, previous IPE read back");

@Include ("Authenticate.Inc");
Tx = 9012 IpeNo 00 00;
Rx = @ReaderA.Apdu("Read Ipe #" :: IpeNo, Tx);  HashAcc = @Sha256.Update(HashAcc, Tx);  HashAcc = @Sha256.Update(HashAcc, Rx);
@Test(Rx[5..¬2] == Committed, "Case " :: Case :: ": update gone after a reset, previous IPE read back");
