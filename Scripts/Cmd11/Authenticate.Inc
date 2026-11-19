// Authenticate.Inc
//
//  Include file (not a test). Cold resets both readers, selects the card,
//  authenticates it with the ISAM (static or pseudo UID), verifies the
//  directory and starts a new session hash.
//
//  The cold reset drops the field, so the card reloads its image from NVM:
//  anything not committed by an earlier End Session is gone.
//
//  The including script must declare beforehand:
//      SW_OK, CardSelect, HashAcc,
//      RaResp, RaFci, Ra6F, RaA5, RaShell, RaDir, RaChal, RaPUid, RaSUid,
//      RaKas, RaBody, RaIsam, RaMedia
//

@ReaderA.Reset.cold;
@ReaderB.Reset.cold;

RaResp = @ReaderB.Apdu("Isam Password", 90 18 00 00  10  @Itso.PwdI2F);
@Assert(RaResp[¬1..] == SW_OK, "Isam password OK?");

RaFci   = @ReaderA.Apdu("Media Select", CardSelect);
@Assert(RaFci[¬1..] == SW_OK, "Select OK?");
Ra6F    = @Tlv(6F, RaFci);
RaA5    = @Tlv(A5, Ra6F);
RaShell = @Tlv(C0, RaA5);
RaDir   = @Tlv(C2, RaA5);
RaChal  = @Tlv(C5, RaA5);
RaPUid  = @Tlv(C6, RaA5);
RaSUid  = @Tlv(C7, RaA5);
RaKas   = @Tlv(C8, RaA5);

if (RaPUid.Length != 0) {                                                         // Pseudo UID: authenticate that first
    RaBody  = @Itso.DateX RaShell RaPUid RaChal;
    RaIsam  = @ReaderB.Apdu("Isam Begin (pseudo)", 90 48 00 RaKas[0] RaBody.Length RaBody 00);
    @Assert(RaIsam[¬1..] == SW_OK, "Begin OK?");
    RaMedia = @ReaderA.Apdu("Media Authenticate (pseudo)", 90 10 00 00 (RaIsam.Length-2) RaIsam[..¬2] 08);
    @Assert(RaMedia[¬1..] == SW_OK, "Authenticate OK?");
    RaResp  = @ReaderB.Apdu("Isam External Authenticate (pseudo)", 00 82 00 RaKas[1] (RaMedia.Length-2) RaMedia[..¬2]);
    @Assert(RaResp[¬1..] == SW_OK, "External Authenticate OK?");

    RaFci   = @ReaderA.Apdu("Media Reselect", 9022 0000 00);
    @Assert(RaFci[¬1..] == SW_OK, "Reselect OK?");
    Ra6F    = @Tlv(6F, RaFci);
    RaA5    = @Tlv(A5, Ra6F);
    RaShell = @Tlv(C0, RaA5);
    RaDir   = @Tlv(C2, RaA5);
    RaChal  = @Tlv(C5, RaA5);
    RaSUid  = @Tlv(C7, RaA5);
    RaKas   = @Tlv(C8, RaA5);

    RaResp  = @ReaderB.Apdu("Isam End (pseudo)", 90 58 00 00 00);
    @Assert(RaResp[¬1..] == SW_OK, "End OK?");
}

RaBody  = @Itso.DateX RaShell RaSUid RaChal;
RaIsam  = @ReaderB.Apdu("Isam Begin", 90 48 00 RaKas[0] RaBody.Length RaBody 00);
@Assert(RaIsam[¬1..] == SW_OK, "Begin OK?");
RaMedia = @ReaderA.Apdu("Media Authenticate", 90 10 00 00 (RaIsam.Length-2) RaIsam[..¬2] 08);
@Assert(RaMedia[¬1..] == SW_OK, "Authenticate OK?");
RaResp  = @ReaderB.Apdu("Isam External Authenticate", 00 82 00 RaKas[1] (RaMedia.Length-2) RaMedia[..¬2]);
@Assert(RaResp[¬1..] == SW_OK, "External Authenticate OK?");

RaResp  = @ReaderB.Apdu("WSAM Dir", 9040 0002 ((u8)(2 + RaDir.Length)) ((u16)RaDir.Length) RaDir);
RaResp  = @ReaderB.Apdu("VERIFY_ITSO", 904E 0000 00);
@Assert(RaResp[¬1..] == SW_OK, "Verify Directory");

HashAcc = @Sha256.init;                                                           // new session, new hash
