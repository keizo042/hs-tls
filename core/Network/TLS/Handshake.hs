-- |
-- Module      : Network.TLS.Handshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake
    ( handshake
    , handshakeWith
    , handshakeClientWith
    , handshakeServerWith
    , handshakeClient
    , handshakeServer
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.IO
import Network.TLS.Util (catchException)

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Server

import Control.Monad.State.Strict
import Control.Exception (fromException)

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation
handshake :: MonadIO m => Context -> m ()
handshake ctx =
    liftIO $ handleException ctx $ withRWLock ctx (ctxDoHandshake ctx $ ctx)

-- Handshake when requested by the remote end
-- This is called automatically by 'recvData'
handshakeWith :: MonadIO m => Context -> Handshake -> m ()
handshakeWith ctx hs =
    liftIO $ handleException ctx $ withRWLock ctx ((ctxDoHandshakeWith ctx) ctx hs)

handleException :: Context -> IO () -> IO ()
handleException ctx f = catchException f $ \exception -> do
    let tlserror = maybe (Error_Misc $ show exception) id $ fromException exception
    setEstablished ctx NotEstablished
    tls13 <- tls13orLater ctx
    if tls13 then
        sendPacket13 ctx $ Alert13 $ errorToAlert tlserror
      else
        sendPacket ctx $ Alert $ errorToAlert tlserror
    handshakeFailed tlserror
