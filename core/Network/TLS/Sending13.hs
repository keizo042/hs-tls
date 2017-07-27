-- |
-- Module      : Network.TLS.Sending
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Sending module contains calls related to marshalling packets according
-- to the TLS state
--
module Network.TLS.Sending13 (writePacket13, writeHandshakePacket13) where

import Control.Monad.State

import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Record (RecordM)
import Network.TLS.Record.Types13
import Network.TLS.Record.Engage13
import Network.TLS.Packet
import Network.TLS.Packet13
import Network.TLS.Hooks
import Network.TLS.Context.Internal
import Network.TLS.Handshake.State
import Network.TLS.Wire

makeRecord :: Packet13 -> RecordM Record13
makeRecord pkt = return $ Record13 (contentType pkt) $ writePacketContent pkt
  where writePacketContent (Handshake13 hss) = encodeHandshakes13 hss
        writePacketContent (Alert13 a)       = encodeAlerts a
        writePacketContent (AppData13 x)     = x

encodeRecord :: Record13 -> RecordM ByteString
encodeRecord (Record13 ct bytes) = return ebytes
  where
    ebytes = runPut $ do
        putWord8 $ fromIntegral $ valOfType ct
        putWord16 0x0301
        putWord16 $ fromIntegral $ B.length bytes
        putBytes bytes

writePacket13 :: Context -> Packet13 -> IO (Either TLSError ByteString)
writePacket13 ctx pkt@(Handshake13 hss) = do
    forM_ hss $ \hs -> usingHState ctx $ do
        let encoded = encodeHandshake13 hs
        updateHandshakeDigest encoded
        addHandshakeMessage encoded
    prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)
writePacket13 ctx pkt = prepareRecord ctx (makeRecord pkt >>= engageRecord >>= encodeRecord)

writeHandshakePacket13 :: MonadIO m => Context -> Handshake13 -> m ByteString
writeHandshakePacket13 ctx hdsk = do
    let pkt = Handshake13 [hdsk]
    edataToSend <- liftIO $ do
        withLog ctx $ \logging -> loggingPacketSent logging (show pkt)
        writePacket13 ctx pkt
    case edataToSend of
        Left err         -> throwCore err
        Right dataToSend -> return dataToSend

prepareRecord :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord = runTxState
