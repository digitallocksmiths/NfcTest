// DirWrite.Inc
//
//  Include file (not a test). Counts Step, sends Update Dir (901E) with
//  directory ExpDir and the directory password, adds the exchange to the
//  session hash and checks it is accepted. Follow it with DirProbe.Inc to
//  check the card is using the new directory.
//
//  The including script must declare beforehand:
//      SW_OK, HashAcc, Tx, Rx, DirPwd, ExpDir, Step (u8)
//

Step = Step + 1;
Tx = 901E 0000 ((u8)(DirPwd.Length + ExpDir.Length)) DirPwd ExpDir;
Rx = @ReaderA.Apdu("Update Dir (write " :: Step :: ")", Tx);  HashAcc = @Sha256.Update(HashAcc, Tx);  HashAcc = @Sha256.Update(HashAcc, Rx);
@Test(Rx[¬1..] == SW_OK, "Update Dir accepted (write " :: Step :: ")");
