// Commit.Inc
//
//  Include file (not a test). Has the ISAM sign the session hash, sends
//  End Session to the card and checks that the card and ISAM proofs match.
//
//  The including script must declare beforehand:
//      SW_OK, HashAcc, Hash, Sig, CmProof, IsamProof, Rx
//

Hash = @Sha256.Final(HashAcc);

Rx = @ReaderB.Apdu("WSAM", 9040 0002 ((u8)(2 + Hash.Length)) ((u16)Hash.Length) Hash);
@Assert(Rx[¬1..] == SW_OK, "WSAM");

Rx = @ReaderB.Apdu("PIMO", 904A000004 00040020 00);
@Assert(Rx[¬1..] == SW_OK, "PIMO");
Sig = Rx[..¬2];

Rx = @ReaderA.Apdu("End Session", 9020 0000 ((u8)Sig.length) Sig 00);
@Test(Rx[¬1..] == SW_OK, "End Session (commit) accepted");
CmProof = Rx[..¬2];

Rx = @ReaderB.Apdu("WSAM", 9040 0002 ((u8)(2 + Sig.Length)) ((u16)Sig.Length) Sig);
@Assert(Rx[¬1..] == SW_OK, "WSAM");

Rx = @ReaderB.Apdu("PIMO", 904A000004 00040008 00);
@Assert(Rx[¬1..] == SW_OK, "PIMO");
IsamProof = Rx[..¬2];

@Test(CmProof == IsamProof, "Card and ISAM session signatures match");
