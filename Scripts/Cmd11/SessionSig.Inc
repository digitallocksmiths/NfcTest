// SessionSig.Inc
//
//  Include file (not a test). Has the ISAM sign the session hash, leaving
//  the End Session signature in Sig. Nothing is sent to the card: the
//  including script decides how to send it. (Commit.Inc does the same and
//  then sends a correct End Session.)
//
//  The including script must declare beforehand:
//      SW_OK, HashAcc, Hash, Sig, Rx
//

Hash = @Sha256.Final(HashAcc);

Rx = @ReaderB.Apdu("WSAM", 9040 0002 ((u8)(2 + Hash.Length)) ((u16)Hash.Length) Hash);
@Assert(Rx[¬1..] == SW_OK, "WSAM");

Rx = @ReaderB.Apdu("PIMO", 904A000004 00040020 00);
@Assert(Rx[¬1..] == SW_OK, "PIMO");
Sig = Rx[..¬2];
