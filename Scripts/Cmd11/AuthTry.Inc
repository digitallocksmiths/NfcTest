// AuthTry.Inc
//
//  Include file (not a test). Has the ISAM answer the challenge in the FCI
//  last parsed by FciParse.Inc, and sends that answer to the card as Media
//  Authenticate. Uses the pseudo UID when the FCI has one, otherwise the
//  static UID. The caller checks MediaRx (and sends the ISAM External
//  Authenticate when it wants the ISAM to finish).
//
//  The ISAM is sent Isam End first, unchecked: Isam Begin fails while an
//  earlier Begin is still open, and Isam End may fail when none is.
//
//  The including script must declare beforehand:
//      SW_OK, Rx, RsShell, RsPUid, RsSUid, RsChal, RsKas, Uid, Body,
//      IsamRx, MediaTx, MediaRx
//

Rx = @ReaderB.Apdu("Isam End (tidy up)", 90 58 00 00 00);
if (RsPUid.Length != 0) { Uid = RsPUid; } else { Uid = RsSUid; }
Body    = @Itso.DateX RsShell Uid RsChal;
IsamRx  = @ReaderB.Apdu("Isam Begin", 90 48 00 RsKas[0] Body.Length Body 00);
@Assert(IsamRx[¬1..] == SW_OK, "Begin OK?");
MediaTx = 9010 0000 ((u8)(IsamRx.Length-2)) IsamRx[..¬2] 08;
MediaRx = @ReaderA.Apdu("Media Authenticate", MediaTx);
