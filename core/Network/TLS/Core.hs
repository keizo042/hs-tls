{-# OPTIONS_HADDOCK hide #-}
{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}
-- |
-- Module      : Network.TLS.Core
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Core
    (
    -- * Internal packet sending and receiving
      sendPacket
    , recvPacket

    -- * Initialisation and Termination of context
    , bye
    , handshake

    -- * Application Layer Protocol Negotiation
    , getNegotiatedProtocol

    -- * Server Name Indication
    , getClientSNI

    -- * High level API
    , sendData
    , recvData
    , recvData'
    ) where

import Network.TLS.Cipher
import Network.TLS.Context
import Network.TLS.Crypto
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.State (getSession)
import Network.TLS.Parameters
import Network.TLS.IO
import Network.TLS.Session
import Network.TLS.Handshake
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.KeySchedule
import Network.TLS.Record.State
import Network.TLS.Util (catchException)
import qualified Network.TLS.State as S
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import qualified Data.ByteString.Lazy as L
import qualified Control.Exception as E
import Control.Concurrent.MVar (readMVar)

import Control.Monad.State.Strict

-- | notify the context that this side wants to close connection.
-- this is important that it is called before closing the handle, otherwise
-- the session might not be resumable (for version < TLS1.2).
--
-- this doesn't actually close the handle
bye :: MonadIO m => Context -> m ()
bye ctx = do
    tls13 <- tls13orLater ctx
    if tls13 then
        sendPacket13 ctx $ Alert13 [(AlertLevel_Warning, CloseNotify)]
      else
        sendPacket ctx $ Alert [(AlertLevel_Warning, CloseNotify)]

-- | If the ALPN extensions have been used, this will
-- return get the protocol agreed upon.
getNegotiatedProtocol :: MonadIO m => Context -> m (Maybe B.ByteString)
getNegotiatedProtocol ctx = liftIO $ usingState_ ctx S.getNegotiatedProtocol

type HostName = String

-- | If the Server Name Indication extension has been used, return the
-- hostname specified by the client.
getClientSNI :: MonadIO m => Context -> m (Maybe HostName)
getClientSNI ctx = liftIO $ usingState_ ctx S.getClientSNI

-- | sendData sends a bunch of data.
-- It will automatically chunk data to acceptable packet size
sendData :: MonadIO m => Context -> L.ByteString -> m ()
sendData ctx dataToSend = do
    tls13 <- tls13orLater ctx
    let sendP
          | tls13     = sendPacket13 ctx . AppData13
          | otherwise = sendPacket ctx . AppData
    let sendDataChunk d
            | B.length d > 16384 = do
                let (sending, remain) = B.splitAt 16384 d
                sendP sending
                sendDataChunk remain
            | otherwise = sendP d
    liftIO (checkValid ctx) >> mapM_ sendDataChunk (L.toChunks dataToSend)

-- | recvData get data out of Data packet, and automatically renegotiate if
-- a Handshake ClientHello is received
recvData :: MonadIO m => Context -> m B.ByteString
recvData ctx = do
    tls13 <- tls13orLater ctx
    if tls13 then recvData13 ctx else recvData1 ctx

recvData1 :: MonadIO m => Context -> m B.ByteString
recvData1 ctx = liftIO $ do
    checkValid ctx
    pkt <- withReadLock ctx $ recvPacket ctx
    either (onError terminate) process pkt
  where process (Handshake [ch@(ClientHello {})]) =
            handshakeWith ctx ch >> recvData1 ctx
        process (Handshake [hr@HelloRequest]) =
            handshakeWith ctx hr >> recvData1 ctx

        process (Alert [(AlertLevel_Warning, CloseNotify)]) = tryBye ctx >> setEOF ctx >> return B.empty
        process (Alert [(AlertLevel_Fatal, desc)]) = do
            setEOF ctx
            E.throwIO (Terminated True ("received fatal error: " ++ show desc) (Error_Protocol ("remote side fatal error", True, desc)))

        -- when receiving empty appdata, we just retry to get some data.
        process (AppData "") = recvData1 ctx
        process (AppData x)  = return x
        process p            = let reason = "unexpected message " ++ show p in
                               terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

        terminate = terminate' ctx (\x -> sendPacket ctx $ Alert x)

recvData13 :: MonadIO m => Context -> m B.ByteString
recvData13 ctx = liftIO $ do
    checkValid ctx
    pkt <- withReadLock ctx $ recvPacket13 ctx
    either (onError terminate) process pkt
  where process (Alert13 [(AlertLevel_Warning, CloseNotify)]) = tryBye ctx >> setEOF ctx >> return B.empty
        process (Alert13 [(AlertLevel_Fatal, desc)]) = do
            setEOF ctx
            E.throwIO (Terminated True ("received fatal error: " ++ show desc) (Error_Protocol ("remote side fatal error", True, desc)))
        process (Handshake13 [ClientHello13 _ _ _ _]) = do
            let reason = "Client hello is not allowed"
            terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        process (Handshake13 [EndOfEarlyData13]) = do
            alertAction <- popPendingAction ctx
            alertAction "dummy"
            recvData13 ctx
        process (Handshake13 [Finished13 verifyData']) = do
            finishedAction <- popPendingAction ctx
            finishedAction verifyData'
            recvData13 ctx
        process (Handshake13 [NewSessionTicket13 life add nonce ticket _exts]) = do
            Just resumptionMasterSecret <- usingHState ctx getTLS13MasterSecret
            tx <- readMVar (ctxTxState ctx)
            let Just usedCipher = stCipher tx
                usedHash = cipherHash usedCipher
                hashSize = hashDigestSize usedHash
            let psk = hkdfExpandLabel usedHash resumptionMasterSecret "resumption" nonce hashSize
            usingHState ctx $ setTLS13MasterSecret $ Just psk
            mgrp <- usingHState ctx getTLS13Group
            tinfo <- createTLS13TicketInfo life $ Right add
            Just sdata <- getSessionData ctx mgrp (Just tinfo)
            sessionEstablish (sharedSessionManager $ ctxShared ctx) ticket sdata
            putStrLn $ "NewSessionTicket received: lifetime = " ++ show life
            recvData13 ctx
        -- when receiving empty appdata, we just retry to get some data.
        process (AppData13 "") = recvData13 ctx
        process (AppData13 x) = do
            established <- ctxEstablished ctx
            when (established == EarlyDataAllowed) $ do
                putStrLn "---- EARLY DATA ----"
                B.putStrLn x
            if established == EarlyDataNotAllowed then
                recvData13 ctx
              else
                return x
        process p             = let reason = "unexpected message " ++ show p in
                                terminate (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

        terminate = terminate' ctx (\x -> sendPacket13 ctx $ Alert13 x)

-- this in a try and ignore all exceptions
tryBye :: Context -> IO ()
tryBye ctx = catchException (bye ctx) (\_ -> return ())

onError :: Monad m => (TLSError -> AlertLevel -> AlertDescription -> String -> m B.ByteString)
                   -> TLSError -> m B.ByteString
onError _ Error_EOF = -- Not really an error.
            return B.empty
onError terminate err@(Error_Protocol (reason,fatal,desc)) =
    terminate err (if fatal then AlertLevel_Fatal else AlertLevel_Warning) desc reason
onError terminate err =
    terminate err AlertLevel_Fatal InternalError (show err)

terminate' :: Context -> ([(AlertLevel, AlertDescription)] -> IO ())
           -> TLSError -> AlertLevel -> AlertDescription -> String -> IO a
terminate' ctx send err level desc reason = do
    session <- usingState_ ctx getSession
    case session of
        Session Nothing    -> return ()
        Session (Just sid) -> sessionInvalidate (sharedSessionManager $ ctxShared ctx) sid
    catchException (send [(level, desc)]) (\_ -> return ())
    setEOF ctx
    E.throwIO (Terminated False reason err)


{-# DEPRECATED recvData' "use recvData that returns strict bytestring" #-}
-- | same as recvData but returns a lazy bytestring.
recvData' :: MonadIO m => Context -> m L.ByteString
recvData' ctx = recvData ctx >>= return . L.fromChunks . (:[])
