// FciParse.Inc
//
//  Include file (not a test). Splits the FCI in RsFci (a Select or Reselect
//  response, SW included) into its tags. A tag that is not there comes
//  back empty (Length 0).
//
//  The including script must declare beforehand:
//      RsFci, Rs6F, RsA5, RsShell, RsCap, RsDir, RsOid, RsCss, RsChal,
//      RsPUid, RsSUid, RsKas
//

Rs6F    = @Tlv(6F, RsFci);
RsA5    = @Tlv(A5, Rs6F);
RsShell = @Tlv(C0, RsA5);
RsCap   = @Tlv(C1, RsA5);
RsDir   = @Tlv(C2, RsA5);
RsOid   = @Tlv(C3, RsA5);
RsCss   = @Tlv(C4, RsA5);
RsChal  = @Tlv(C5, RsA5);
RsPUid  = @Tlv(C6, RsA5);
RsSUid  = @Tlv(C7, RsA5);
RsKas   = @Tlv(C8, RsA5);
