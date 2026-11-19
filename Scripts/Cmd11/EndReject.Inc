// EndReject.Inc
//
//  Include file (not a test). In a new session, writes a test IPE (Mark),
//  has the ISAM sign the session, then sends EndTx: an End Session built
//  from that real signature but with one thing wrong. Checks:
//      - EndTx is rejected with Expect;
//      - the session is over: Update Ipe now gives 6982, and so does the
//        correct End Session sent after it (it can't be rescued);
//      - the abandoned update is not visible (unauthenticated read, before
//        any reset) and is gone after a reset.
//
//  The including script must declare beforehand:
//      everything Authenticate.Inc and SessionSig.Inc need, SW_SEC, Tx,
//      Rx, Pwd, IpeNo, Mark (u8), Ipe, IpeBody (14 bytes), SealTail
//      (14 bytes), Redacted, Committed, EndTx, EndKind (u8), Expect.
//  EndTx needs the signature, so the script sets EndKind and this file
//  builds EndTx:
//
//  EndKind:  1  P1 = 01             expect 6A86
//            2  P2 = 01             expect 6A86
//            3  Lc = 07             expect 6700
//            4  case 3 (no Le)      expect 6700
//            5  bad MAC             expect 6300
//

@Include ("Authenticate.Inc");

Ipe = 10 Mark IpeBody Mark Mark SealTail;
Tx  = 9018 IpeNo 00 ((u8)(Pwd.Length + Ipe.Length)) Pwd Ipe;
Rx  = @ReaderA.Apdu("Update Ipe, mark " :: Mark, Tx);  HashAcc = @Sha256.Update(HashAcc, Tx);  HashAcc = @Sha256.Update(HashAcc, Rx);
@Test(Rx[¬1..] == SW_OK, "Update Ipe accepted, mark " :: Mark);

@Include ("SessionSig.Inc");

if (EndKind == 1) { EndTx = 9020 0100 08 Sig 00; }
if (EndKind == 2) { EndTx = 9020 0001 08 Sig 00; }
if (EndKind == 3) { EndTx = 9020 0000 07 Sig[0..6] 00; }
if (EndKind == 4) { EndTx = 9020 0000 08 Sig; }
if (EndKind == 5) { EndTx = 9020 0000 08 Sig[1..7] Sig[0] 00; }    // the real MAC, rotated one byte

Rx = @ReaderA.Apdu("End Session (fault " :: EndKind :: ")", EndTx);
@Test(Rx[¬1..] == Expect, "End Session fault " :: EndKind :: " rejected with " :: Expect);

Tx = 9018 IpeNo 00 ((u8)(Pwd.Length + Ipe.Length)) Pwd Ipe;
Rx = @ReaderA.Apdu("Update Ipe after the rejected End Session", Tx);
@Test(Rx[¬1..] == SW_SEC, "Fault " :: EndKind :: ": session over, Update Ipe refused");

Rx = @ReaderA.Apdu("End Session (correct, too late)", 9020 0000 08 Sig 00);
@Test(Rx[¬1..] == SW_SEC, "Fault " :: EndKind :: ": correct End Session afterwards refused, the session can't be rescued");

Rx = @ReaderA.Apdu("Read Ipe #" :: IpeNo :: " (not authenticated)", 9012 IpeNo 00 00);
@Test(Rx[¬1..] == SW_OK, "Read Ipe OK");
@Test(Rx[5..¬2] == Committed[..¬16_d] Redacted, "Fault " :: EndKind :: ": abandoned update not visible before a reset, previous IPE read back");

@Include ("Authenticate.Inc");
Tx = 9012 IpeNo 00 00;
Rx = @ReaderA.Apdu("Read Ipe #" :: IpeNo, Tx);  HashAcc = @Sha256.Update(HashAcc, Tx);  HashAcc = @Sha256.Update(HashAcc, Rx);
@Test(Rx[5..¬2] == Committed, "Fault " :: EndKind :: ": abandoned update gone after a reset, previous IPE read back");
