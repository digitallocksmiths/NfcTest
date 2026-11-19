// UpdateGate.Inc
//
//  Include file (not a test). Sends each update command and End Session,
//  all well formed (right P1/P2, case and length) but with a dummy password
//  / MAC, and checks every one gives Expect:
//      6982 where updates are not permitted: the security check stops them
//           before the password is looked at;
//      6300 where they are (fully authenticated): they get past the
//           security check and fail on the dummy password / MAC.
//  So a 6300 where 6982 is expected shows the card let the command in.
//
//  End Session goes last: when it is let in it ends the session.
//  The exchanges are not hashed: either there is no session, or End
//  Session ends it anyway.
//
//  The including script must declare beforehand:
//      Rx, Expect, Ctx (u8, labels the messages), DirLen (u8), GateDir
//      (DirLen bytes), GatePwd (8 bytes)
//

Rx = @ReaderA.Apdu("Update Ipe (gate " :: Ctx :: ")", 9018 0100 1C GatePwd 04000000 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
@Test(Rx[¬1..] == Expect, "Gate " :: Ctx :: ": Update Ipe gives " :: Expect);

Rx = @ReaderA.Apdu("Update Vrg (gate " :: Ctx :: ")", 901A 0100 1C GatePwd 04000000 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
@Test(Rx[¬1..] == Expect, "Gate " :: Ctx :: ": Update Vrg gives " :: Expect);

Rx = @ReaderA.Apdu("Update Log (gate " :: Ctx :: ")", 901C 0000 10 GatePwd 0102030405060708);
@Test(Rx[¬1..] == Expect, "Gate " :: Ctx :: ": Update Log gives " :: Expect);

Rx = @ReaderA.Apdu("Update Dir (gate " :: Ctx :: ")", 901E 0000 ((u8)(8 + DirLen)) GatePwd GateDir);
@Test(Rx[¬1..] == Expect, "Gate " :: Ctx :: ": Update Dir gives " :: Expect);

Rx = @ReaderA.Apdu("End Session (gate " :: Ctx :: ")", 9020 0000 08 0000000000000000 00);
@Test(Rx[¬1..] == Expect, "Gate " :: Ctx :: ": End Session gives " :: Expect);
