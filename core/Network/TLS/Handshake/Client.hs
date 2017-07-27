{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}

-- |
-- Module      : Network.TLS.Handshake.Client
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Client
    ( handshakeClient
    , handshakeClientWith
    ) where

import Network.TLS.Crypto
import Network.TLS.Context.Internal
import Network.TLS.Parameters
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Packet hiding (getExtensions)
import Network.TLS.Packet13
import Network.TLS.ErrT
import Network.TLS.Extension
import Network.TLS.IO
import Network.TLS.Sending13
import Network.TLS.Imports
import Network.TLS.State hiding (getNegotiatedProtocol)
import Network.TLS.Measurement
import Network.TLS.Util (bytesEq, catchException)
import Network.TLS.Types
import Network.TLS.X509
import Data.Maybe hiding (fromJust)
import Data.List (find, intersect)
import qualified Data.ByteString as B
import Data.ByteString.Char8 ()
import Data.Typeable

import Control.Monad.State.Strict
import Control.Exception (SomeException, Exception)
import qualified Control.Exception as E

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Certificate
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.KeySchedule
import Network.TLS.Extra.Cipher

import Network.TLS.Wire

handshakeClientWith :: ClientParams -> Context -> Handshake -> IO ()
handshakeClientWith cparams ctx HelloRequest = handshakeClient cparams ctx
handshakeClientWith _       _   _            = throwCore $ Error_Protocol ("unexpected handshake message received in handshakeClientWith", True, HandshakeFailure)

data HelloSwitch = SwitchTLS13 !CipherID [ExtensionRaw]
                 | HelloRetry !Version !CipherID [ExtensionRaw]
                 deriving (Show, Typeable)

instance Exception HelloSwitch

-- client part of handshake. send a bunch of handshake of client
-- values intertwined with response from the server.
handshakeClient :: ClientParams -> Context -> IO ()
handshakeClient cparams ctx = do
    let groups' = supportedGroups (ctxSupported ctx) `intersect` availableGroups
        groups = case clientWantSessionResume cparams of
              Nothing         -> groups'
              Just (_, sdata) -> case sessionGroup sdata of
                  Nothing  -> [] -- TLS 1.2 or earlier
                  Just grp -> [grp]
    handshakeClient' cparams ctx groups Nothing

handshakeClient' :: ClientParams -> Context -> [Group] -> Maybe ClientRandom -> IO ()
handshakeClient' cparams ctx groups mcrand = do
    putStr $ "groups = " ++ show groups ++ ", keyshare = ["
    case groups of
        []  -> putStrLn "]"
        g:_ -> putStrLn $ show g ++ "]"
    updateMeasure ctx incrementNbHandshakes
    sentExtensions <- sendClientHello mcrand
    ech <- E.try $ recvServerHello sentExtensions
    case ech of
        Left (SwitchTLS13 cipher exts) -> handshakeClient13 cparams ctx cipher exts
        Left (HelloRetry _ver _usedCipher exts) -> case drop 1 groups of
            []      -> error "HRR: no common group" -- fixme
            groups' -> case extensionLookup extensionID_KeyShare exts >>= extensionDecode MsgTHelloRetryRequest of
              Just (KeyShareHRR selectedGroup)
                | selectedGroup `elem` groups' -> do
                      putStrLn "Retrying client hello..."
                      usingHState ctx $ setTLS13HRR True
                      crand <- usingHState ctx $ hstClientRandom <$> get
                      handshakeClient' cparams ctx [selectedGroup] (Just crand)
              _                    -> error "HRR: no common group" -- fixme
        Right () -> do
            putStrLn "TLS 1.2"
            sessionResuming <- usingState_ ctx isSessionResuming
            if sessionResuming
                then sendChangeCipherAndFinish ctx ClientRole
                else do sendClientData cparams ctx
                        sendChangeCipherAndFinish ctx ClientRole
                        recvChangeCipherAndFinish ctx
            handshakeTerminate ctx
  where ciphers      = supportedCiphers $ ctxSupported ctx
        compressions = supportedCompressions $ ctxSupported ctx
        highestVer = maximum $ supportedVersions $ ctxSupported ctx
        tls13 = highestVer >= TLS13ID21
        getExtensions = sequence [sniExtension
                                 ,secureReneg
                                 ,alpnExtension
                                 ,curveExtension
                                 ,ecPointExtension
                                 --,sessionTicketExtension
                                 ,signatureAlgExtension
                                 -- ,heartbeatExtension
                                 ,versionExtension
                                 ,earlyDataExtension
                                 ,keyshareExtension
                                 ,pskExchangeModeExtension
                                 ,preSharedKeyExtension
                                 ]

        toExtensionRaw :: Extension e => e -> ExtensionRaw
        toExtensionRaw ext = ExtensionRaw (extensionID ext) (extensionEncode ext)

        secureReneg  =
                if supportedSecureRenegotiation $ ctxSupported ctx
                then usingState_ ctx (getVerifiedData ClientRole) >>= \vd -> return $ Just $ toExtensionRaw $ SecureRenegotiation vd Nothing
                else return Nothing
        alpnExtension = do
            mprotos <- onSuggestALPN $ clientHooks cparams
            case mprotos of
                Nothing -> return Nothing
                Just protos -> do
                    usingState_ ctx $ setClientALPNSuggest protos
                    return $ Just $ toExtensionRaw $ ApplicationLayerProtocolNegotiation protos
        sniExtension = if clientUseServerNameIndication cparams
                         then do let sni = fst $ clientServerIdentification cparams
                                 usingState_ ctx $ setClientSNI sni
                                 return $ Just $ toExtensionRaw $ ServerName [ServerNameHostName sni]
                         else return Nothing

        curveExtension = return $ Just $ toExtensionRaw $ NegotiatedGroups ((supportedGroups $ ctxSupported ctx) `intersect` availableGroups)
        ecPointExtension = return $ Just $ toExtensionRaw $ EcPointFormatsSupported [EcPointFormat_Uncompressed]
                                --[EcPointFormat_Uncompressed,EcPointFormat_AnsiX962_compressed_prime,EcPointFormat_AnsiX962_compressed_char2]
        --heartbeatExtension = return $ Just $ toExtensionRaw $ HeartBeat $ HeartBeat_PeerAllowedToSend
        --sessionTicketExtension = return $ Just $ toExtensionRaw $ SessionTicket

        signatureAlgExtension = return $ Just $ toExtensionRaw $ SignatureAlgorithms $ supportedHashSignatures $ clientSupported cparams

        versionExtension
          | tls13 = do
                let vers = filter (>= TLS12) $ supportedVersions $ ctxSupported ctx
                return $ Just $ toExtensionRaw $ SupportedVersions vers
          | otherwise = return Nothing

        -- FIXME
        keyshareExtension
          | tls13 = case groups of
                  []    -> return Nothing
                  grp:_ -> do
                      (cpri, ent) <- makeClientKeyShare ctx grp
                      usingHState ctx $ setGroupPrivate cpri
                      return $ Just $ toExtensionRaw $ KeyShareClientHello [ent]
          | otherwise = return Nothing

        sessionHash sdata = case cipherIDtoCipher13 (sessionCipher sdata) of
          Just cipher -> cipherHash cipher
          Nothing     -> error "sessionHash"

        preSharedKeyExtension
          | not tls13 = return Nothing
          | otherwise = case clientWantSessionResume cparams of
              Nothing -> return Nothing
              Just (sid, sdata)
                | sessionVersion sdata >= TLS13ID21 -> do
                      let usedHash = sessionHash sdata
                          siz = hashDigestSize usedHash
                          zero = B.replicate siz 0
                          Just tinfo = sessionTicketInfo sdata -- fixme
                      age <- getAge tinfo
                      if isAgeValid age tinfo then do
                          let obfAge = ageToObfuscatedAge age tinfo
                          let identity = PskIdentity sid obfAge
                              psk = PreSharedKeyClientHello [identity] [zero]
                          return $ Just $ toExtensionRaw psk
                        else
                          return Nothing
                | otherwise                         -> return Nothing

        pskExchangeModeExtension
          | tls13     = return $ Just $ toExtensionRaw $ PskKeyExchangeModes [PSK_DHE_KE]
          | otherwise = return Nothing

        earlyDataExtension = case checkZeroRTT of
            Nothing -> return $ Nothing
            _       -> return $ Just $ toExtensionRaw (EarlyDataIndication Nothing)

        clientSession = case clientWantSessionResume cparams of
            Nothing -> Session Nothing
            Just (sid, sdata)
              | sessionVersion sdata >= TLS13ID21 -> Session Nothing
              | otherwise                         -> Session (Just sid)

        adjustExtentions exts ch
          | not tls13 = return exts
          | otherwise = case clientWantSessionResume cparams of
              Nothing -> return exts
              Just (_, sdata)
                | sessionVersion sdata >= TLS13ID21 -> do
                      let usedHash = sessionHash sdata
                          siz = hashDigestSize usedHash
                          zero = B.replicate siz 0
                          psk = sessionSecret sdata
                          earlySecret = hkdfExtract usedHash zero psk
                      usingHState ctx $ setTLS13MasterSecret (Just earlySecret)
                      let ech = encodeHandshake ch
                      binder <- makePSKBinder ctx earlySecret usedHash (siz + 3) (Just ech)
                      let exts' = init exts ++ [adjust (last exts)]
                          adjust (ExtensionRaw eid pskz) = (ExtensionRaw eid pskb)
                            where
                              pskb = replacePSKBinder pskz binder
                      return exts'
                | otherwise                         -> return exts

        sendClientHello mcr = do
            -- fixme -- "44 4F 57 4E 47 52 44 01"
            crand <- case mcr of
              Nothing -> getStateRNG ctx 32 >>= return . ClientRandom
              Just cr -> return cr
            startHandshake ctx highestVer crand
            usingState_ ctx $ setVersionIfUnset highestVer
            let ver = if tls13 then TLS12 else highestVer
                cipherIds = map cipherID ciphers
                compIds = map compressionID compressions
                mkClientHello exts = ClientHello ver crand clientSession cipherIds compIds exts Nothing
            extensions0 <- catMaybes <$> getExtensions
            extensions <- adjustExtentions extensions0 $ mkClientHello extensions0
            sendPacket ctx $ Handshake [mkClientHello extensions]
            sendZeroRTT
            return $ map (\(ExtensionRaw i _) -> i) extensions

        checkZeroRTT = case clientWantSessionResume cparams of
            Just (_, sdata)
              | sessionVersion sdata >= TLS13ID21 -> case client0RTTData cparams of
                Just earlyData -> Just (sessionCipher sdata, earlyData)
                Nothing        -> Nothing
            _ -> Nothing

        sendZeroRTT = case checkZeroRTT of
            Nothing -> return ()
            Just (cid, earlyData) -> do
                let usedCipher = case cipherIDtoCipher13 cid of
                        Just cipher -> cipher
                        _           -> error "0RTT" -- fixme
                    usedHash = cipherHash usedCipher
                -- fixme: not initialized yet
                -- hCh <- transcriptHash ctx
                hmsgs <- usingHState ctx getHandshakeMessages
                let hCh = hash usedHash $ B.concat hmsgs -- XXX
                Just earlySecret <- usingHState ctx getTLS13MasterSecret -- fixme
                let clientEarlyTrafficSecret = deriveSecret usedHash earlySecret "c e traffic" hCh
{-
                putStrLn $ "hCh: " ++ showBytesHex hCh
                putStrLn $ "clientEarlyTrafficSecret: " ++ showBytesHex clientEarlyTrafficSecret
                putStrLn "---- setTxState ctx usedHash usedCipher clientEarlyTrafficSecret"
-}
                setTxState ctx usedHash usedCipher clientEarlyTrafficSecret
                -- fixme
                Right eEarlyData <- writePacket13 ctx $ AppData13 earlyData
                sendBytes13 ctx eEarlyData
                usingHState ctx $ setTLS13RTT0Status RTT0Sent
                putStrLn "Sending 0RTT data..."

        recvServerHello sentExts = runRecvState ctx recvState
          where recvState = RecvStateNext $ \p ->
                    case p of
                        Handshake [hrr@(HelloRetryRequest ver cid exts)] -> do
                            update' ctx hrr
                            let Just cipher = cipherIDtoCipher13 cid
                            usingHState ctx $ setHelloParameters13 cipher True
                            E.throwIO $ HelloRetry ver cid exts
                        Handshake [sh@(ServerHello' _ _ cid es)] -> do
                            update' ctx sh
                            E.throwIO $ SwitchTLS13 cid es
                        Handshake hs -> onRecvStateHandshake ctx (RecvStateHandshake $ onServerHello ctx cparams sentExts) hs
                        Alert a      ->
                            case a of
                                [(AlertLevel_Warning, UnrecognizedName)] ->
                                    if clientUseServerNameIndication cparams
                                        then return recvState
                                        else throwAlert a
                                _ -> throwAlert a
                        _ -> fail ("unexepected type received. expecting handshake and got: " ++ show p)
                throwAlert a = usingState_ ctx $ throwError $ Error_Protocol ("expecting server hello, got alert : " ++ show a, True, HandshakeFailure)

-- | send client Data after receiving all server data (hello/certificates/key).
--
--       -> [certificate]
--       -> client key exchange
--       -> [cert verify]
sendClientData :: ClientParams -> Context -> IO ()
sendClientData cparams ctx = sendCertificate >> sendClientKeyXchg >> sendCertificateVerify
  where
        -- When the server requests a client certificate, we
        -- fetch a certificate chain from the callback in the
        -- client parameters and send it to the server.
        -- Additionally, we store the private key associated
        -- with the first certificate in the chain for later
        -- use.
        --
        sendCertificate = do
            certRequested <- usingHState ctx getClientCertRequest
            case certRequested of
                Nothing ->
                    return ()

                Just req -> do
                    certChain <- liftIO $ (onCertificateRequest $ clientHooks cparams) req `catchException`
                                 throwMiscErrorOnException "certificate request callback failed"

                    usingHState ctx $ setClientCertSent False
                    case certChain of
                        Nothing                       -> sendPacket ctx $ Handshake [Certificates (CertificateChain [])]
                        Just (CertificateChain [], _) -> sendPacket ctx $ Handshake [Certificates (CertificateChain [])]
                        Just (cc@(CertificateChain (c:_)), pk) -> do
                            case certPubKey $ getCertificate c of
                                PubKeyRSA _ -> return ()
                                PubKeyDSA _ -> return ()
                                _           -> throwCore $ Error_Protocol ("no supported certificate type", True, HandshakeFailure)
                            usingHState ctx $ setPrivateKey pk
                            usingHState ctx $ setClientCertSent True
                            sendPacket ctx $ Handshake [Certificates cc]

        sendClientKeyXchg = do
            cipher <- usingHState ctx getPendingCipher
            ckx <- case cipherKeyExchange cipher of
                CipherKeyExchange_RSA -> do
                    clientVersion <- usingHState ctx $ gets hstClientVersion
                    (xver, prerand) <- usingState_ ctx $ (,) <$> getVersion <*> genRandom 46

                    let premaster = encodePreMasterSecret clientVersion prerand
                    usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                    encryptedPreMaster <- do
                        -- SSL3 implementation generally forget this length field since it's redundant,
                        -- however TLS10 make it clear that the length field need to be present.
                        e <- encryptRSA ctx premaster
                        let extra = if xver < TLS10
                                        then B.empty
                                        else encodeWord16 $ fromIntegral $ B.length e
                        return $ extra `B.append` e
                    return $ CKX_RSA encryptedPreMaster
                CipherKeyExchange_DHE_RSA -> getCKX_DHE
                CipherKeyExchange_DHE_DSS -> getCKX_DHE
                CipherKeyExchange_ECDHE_RSA -> getCKX_ECDHE
                CipherKeyExchange_ECDHE_ECDSA -> getCKX_ECDHE
                _ -> throwCore $ Error_Protocol ("client key exchange unsupported type", True, HandshakeFailure)
            sendPacket ctx $ Handshake [ClientKeyXchg ckx]
          where getCKX_DHE = do
                    xver <- usingState_ ctx getVersion
                    serverParams <- usingHState ctx getServerDHParams
                    (clientDHPriv, clientDHPub) <- generateDHE ctx (serverDHParamsToParams serverParams)

                    let premaster = dhGetShared (serverDHParamsToParams serverParams)
                                                clientDHPriv
                                                (serverDHParamsToPublic serverParams)
                    usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster

                    return $ CKX_DH clientDHPub

                getCKX_ECDHE = do
                    ServerECDHParams _grp srvpub <- usingHState ctx getServerECDHParams
                    ecdhePair <- generateECDHEShared ctx srvpub
                    case ecdhePair of
                        Nothing                  -> throwCore $ Error_Protocol ("invalid server public key", True, HandshakeFailure)
                        Just (clipub, premaster) -> do
                            xver <- usingState_ ctx getVersion
                            usingHState ctx $ setMasterSecretFromPre xver ClientRole premaster
                            return $ CKX_ECDH $ encodeGroupPublic clipub

        -- In order to send a proper certificate verify message,
        -- we have to do the following:
        --
        -- 1. Determine which signing algorithm(s) the server supports
        --    (we currently only support RSA).
        -- 2. Get the current handshake hash from the handshake state.
        -- 3. Sign the handshake hash
        -- 4. Send it to the server.
        --
        sendCertificateVerify = do
            usedVersion <- usingState_ ctx getVersion

            -- Only send a certificate verify message when we
            -- have sent a non-empty list of certificates.
            --
            certSent <- usingHState ctx $ getClientCertSent
            case certSent of
                True -> do
                    sigAlg <- getLocalSignatureAlg

                    mhashSig <- case usedVersion of
                        TLS12 -> do
                            Just (_, Just hashSigs, _) <- usingHState ctx $ getClientCertRequest
                            -- The values in the "signature_algorithms" extension
                            -- are in descending order of preference.
                            -- However here the algorithms are selected according
                            -- to client preference in 'supportedHashSignatures'.
                            let suppHashSigs = supportedHashSignatures $ ctxSupported ctx
                                matchHashSigs = filter (sigAlg `signatureCompatible`) suppHashSigs
                                hashSigs' = filter (\ a -> a `elem` hashSigs) matchHashSigs

                            when (null hashSigs') $
                                throwCore $ Error_Protocol ("no " ++ show sigAlg ++ " hash algorithm in common with the server", True, HandshakeFailure)
                            return $ Just $ head hashSigs'
                        _     -> return Nothing

                    -- Fetch all handshake messages up to now.
                    msgs   <- usingHState ctx $ B.concat <$> getHandshakeMessages
                    sigDig <- createCertificateVerify ctx usedVersion sigAlg mhashSig msgs
                    sendPacket ctx $ Handshake [CertVerify sigDig]

                _ -> return ()

        getLocalSignatureAlg = do
            pk <- usingHState ctx getLocalPrivateKey
            case pk of
                PrivKeyRSA _   -> return RSA
                PrivKeyDSA _   -> return DSS

processServerExtension :: ExtensionRaw -> TLSSt ()
processServerExtension (ExtensionRaw 0xff01 content) = do
    cv <- getVerifiedData ClientRole
    sv <- getVerifiedData ServerRole
    let bs = extensionEncode (SecureRenegotiation cv $ Just sv)
    unless (bs `bytesEq` content) $ throwError $ Error_Protocol ("server secure renegotiation data not matching", True, HandshakeFailure)
    return ()
processServerExtension _ = return ()

throwMiscErrorOnException :: String -> SomeException -> IO a
throwMiscErrorOnException msg e =
    throwCore $ Error_Misc $ msg ++ ": " ++ show e

-- | onServerHello process the ServerHello message on the client.
--
-- 1) check the version chosen by the server is one allowed by parameters.
-- 2) check that our compression and cipher algorithms are part of the list we sent
-- 3) check extensions received are part of the one we sent
-- 4) process the session parameter to see if the server want to start a new session or can resume
-- 5) if no resume switch to processCertificate SM or in resume switch to expectChangeCipher
--
onServerHello :: Context -> ClientParams -> [ExtensionID] -> Handshake -> IO (RecvState IO)
onServerHello ctx cparams sentExts (ServerHello rver serverRan serverSession cipher compression exts) = do
    when (rver == SSL2) $ throwCore $ Error_Protocol ("ssl2 is not supported", True, ProtocolVersion)
    case find ((==) rver) (supportedVersions $ ctxSupported ctx) of
        Nothing -> throwCore $ Error_Protocol ("server version " ++ show rver ++ " is not supported", True, ProtocolVersion)
        Just _  -> return ()
    -- find the compression and cipher methods that the server want to use.
    cipherAlg <- case find ((==) cipher . cipherID) (supportedCiphers $ ctxSupported ctx) of
                     Nothing  -> throwCore $ Error_Protocol ("server choose unknown cipher", True, HandshakeFailure)
                     Just alg -> return alg
    compressAlg <- case find ((==) compression . compressionID) (supportedCompressions $ ctxSupported ctx) of
                       Nothing  -> throwCore $ Error_Protocol ("server choose unknown compression", True, HandshakeFailure)
                       Just alg -> return alg

    -- intersect sent extensions in client and the received extensions from server.
    -- if server returns extensions that we didn't request, fail.
    when (not $ null $ filter (not . flip elem sentExts . (\(ExtensionRaw i _) -> i)) exts) $
        throwCore $ Error_Protocol ("spurious extensions received", True, UnsupportedExtension)

    let resumingSession =
            case clientWantSessionResume cparams of
                Just (sessionId, sessionData) -> if serverSession == Session (Just sessionId) then Just sessionData else Nothing
                Nothing                       -> Nothing
    usingState_ ctx $ do
        setSession serverSession (isJust resumingSession)
        mapM_ processServerExtension exts
        setVersion rver
    usingHState ctx $ setServerHelloParameters rver serverRan cipherAlg compressAlg
    setALPN ctx exts
    case resumingSession of
        Nothing          -> return $ RecvStateHandshake (processCertificate cparams ctx)
        Just sessionData -> do
            usingHState ctx (setMasterSecret rver ClientRole $ sessionSecret sessionData)
            return $ RecvStateNext expectChangeCipher
onServerHello _ _ _ p = unexpected (show p) (Just "server hello")

processCertificate :: ClientParams -> Context -> Handshake -> IO (RecvState IO)
processCertificate cparams ctx (Certificates certs) = do
    -- run certificate recv hook
    ctxWithHooks ctx (\hooks -> hookRecvCertificates hooks $ certs)
    -- then run certificate validation
    usage <- catchException (wrapCertificateChecks <$> checkCert) rejectOnException
    case usage of
        CertificateUsageAccept        -> return ()
        CertificateUsageReject reason -> certificateRejected reason
    return $ RecvStateHandshake (processServerKeyExchange ctx)
  where shared = clientShared cparams
        checkCert = (onServerCertificate $ clientHooks cparams) (sharedCAStore shared)
                                                                (sharedValidationCache shared)
                                                                (clientServerIdentification cparams)
                                                                certs
processCertificate _ ctx p = processServerKeyExchange ctx p

expectChangeCipher :: Packet -> IO (RecvState IO)
expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
expectChangeCipher p                = unexpected (show p) (Just "change cipher")

expectFinish :: Handshake -> IO (RecvState IO)
expectFinish (Finished _) = return RecvStateDone
expectFinish p            = unexpected (show p) (Just "Handshake Finished")

processServerKeyExchange :: Context -> Handshake -> IO (RecvState IO)
processServerKeyExchange ctx (ServerKeyXchg origSkx) = do
    cipher <- usingHState ctx getPendingCipher
    processWithCipher cipher origSkx
    return $ RecvStateHandshake (processCertificateRequest ctx)
  where processWithCipher cipher skx =
            case (cipherKeyExchange cipher, skx) of
                (CipherKeyExchange_DHE_RSA, SKX_DHE_RSA dhparams signature) -> do
                    doDHESignature dhparams signature RSA
                (CipherKeyExchange_DHE_DSS, SKX_DHE_DSS dhparams signature) -> do
                    doDHESignature dhparams signature DSS
                (CipherKeyExchange_ECDHE_RSA, SKX_ECDHE_RSA ecdhparams signature) -> do
                    doECDHESignature ecdhparams signature RSA
                (CipherKeyExchange_ECDHE_ECDSA, SKX_ECDHE_ECDSA ecdhparams signature) -> do
                    doECDHESignature ecdhparams signature ECDSA
                (cke, SKX_Unparsed bytes) -> do
                    ver <- usingState_ ctx getVersion
                    case decodeReallyServerKeyXchgAlgorithmData ver cke bytes of
                        Left _        -> throwCore $ Error_Protocol ("unknown server key exchange received, expecting: " ++ show cke, True, HandshakeFailure)
                        Right realSkx -> processWithCipher cipher realSkx
                    -- we need to resolve the result. and recall processWithCipher ..
                (c,_)           -> throwCore $ Error_Protocol ("unknown server key exchange received, expecting: " ++ show c, True, HandshakeFailure)
        doDHESignature dhparams signature signatureType = do
            -- TODO verify DHParams
            verified <- digitallySignDHParamsVerify ctx dhparams signatureType signature
            when (not verified) $ throwCore $ Error_Protocol ("bad " ++ show signatureType ++ " signature for dhparams " ++ show dhparams, True, HandshakeFailure)
            usingHState ctx $ setServerDHParams dhparams

        doECDHESignature ecdhparams signature signatureType = do
            -- TODO verify DHParams
            verified <- digitallySignECDHParamsVerify ctx ecdhparams signatureType signature
            when (not verified) $ throwCore $ Error_Protocol ("bad " ++ show signatureType ++ " signature for ecdhparams", True, HandshakeFailure)
            usingHState ctx $ setServerECDHParams ecdhparams

processServerKeyExchange ctx p = processCertificateRequest ctx p

processCertificateRequest :: Context -> Handshake -> IO (RecvState IO)
processCertificateRequest ctx (CertRequest cTypes sigAlgs dNames) = do
    -- When the server requests a client
    -- certificate, we simply store the
    -- information for later.
    --
    usingHState ctx $ setClientCertRequest (cTypes, sigAlgs, dNames)
    return $ RecvStateHandshake (processServerHelloDone ctx)
processCertificateRequest ctx p = processServerHelloDone ctx p

processServerHelloDone :: Context -> Handshake -> IO (RecvState m)
processServerHelloDone _ ServerHelloDone = return RecvStateDone
processServerHelloDone _ p = unexpected (show p) (Just "server hello data")

handshakeClient13 :: ClientParams -> Context -> CipherID -> [ExtensionRaw]
                  -> IO ()
handshakeClient13 _cparams ctx cipher exts = do
    usedCipher <- case find ((==) cipher . cipherID) (supportedCiphers $ ctxSupported ctx) of -- FIXME
                     Nothing  -> throwCore $ Error_Protocol ("server choose unknown cipher", True, HandshakeFailure)
                     Just alg -> return alg
    let usedHash = cipherHash usedCipher
    putStrLn $ "TLS 1.3: " ++ show usedCipher ++ " " ++ show usedHash
    usingHState ctx $ setHelloParameters13 usedCipher False
    handshakeClient13' _cparams ctx usedCipher usedHash exts

handshakeClient13' :: ClientParams -> Context -> Cipher -> Hash
                   -> [ExtensionRaw] -> IO ()
handshakeClient13' cparams ctx usedCipher usedHash exts = do
    (resuming, handshakeSecret, clientHandshakeTrafficSecret, serverHandshakeTrafficSecret) <- switchToHandshakeSecret
    rtt0accepted <- recvEncryptedExtensions
    unless resuming recvCertAndVerify
    recvFinished serverHandshakeTrafficSecret
    hChSf <- transcriptHash ctx
    when rtt0accepted $ do
        eoed <- writeHandshakePacket13 ctx EndOfEarlyData13
        sendBytes13 ctx eoed
{-
    putStrLn "---- setTxState ctx usedHash usedCipher clientHandshakeTrafficSecret"
-}
    rawFinished <- makeFinished ctx usedHash clientHandshakeTrafficSecret
    setTxState ctx usedHash usedCipher clientHandshakeTrafficSecret
    writeHandshakePacket13 ctx rawFinished >>= sendBytes13 ctx
    masterSecret <- switchToTrafficSecret handshakeSecret hChSf
    setResumptionSecret masterSecret
    setEstablished ctx Established
  where
    hashSize = hashDigestSize usedHash
    zero = B.replicate hashSize 0

    switchToHandshakeSecret = do
        ecdhe <- calcSharedKey
        (earlySecret, resuming) <- makeEarlySecret
        let handshakeSecret = hkdfExtract usedHash (deriveSecret usedHash earlySecret "derived" (hash usedHash "")) ecdhe
        hChSh <- transcriptHash ctx
        let clientHandshakeTrafficSecret = deriveSecret usedHash handshakeSecret "c hs traffic" hChSh
            serverHandshakeTrafficSecret = deriveSecret usedHash handshakeSecret "s hs traffic" hChSh
{-
        putStrLn $ "earlySecret: " ++ showBytesHex earlySecret
        putStrLn $ "handshakeSecret: " ++ showBytesHex handshakeSecret
        putStrLn $ "hChSh: " ++ showBytesHex hChSh
        usingHState ctx getHandshakeMessages >>= mapM_ (putStrLn . showBytesHex)
        putStrLn $ "serverHandshakeTrafficSecret: " ++ showBytesHex serverHandshakeTrafficSecret
        putStrLn $ "clientHandshakeTrafficSecret: " ++ showBytesHex clientHandshakeTrafficSecret
-}
        setRxState ctx usedHash usedCipher serverHandshakeTrafficSecret
        return (resuming, handshakeSecret, clientHandshakeTrafficSecret, serverHandshakeTrafficSecret)

    switchToTrafficSecret handshakeSecret hChSf = do
        let masterSecret = hkdfExtract usedHash (deriveSecret usedHash handshakeSecret "derived" (hash usedHash "")) zero
        let clientApplicationTrafficSecret0 = deriveSecret usedHash masterSecret "c ap traffic" hChSf
            serverApplicationTrafficSecret0 = deriveSecret usedHash masterSecret "s ap traffic" hChSf
{-
        putStrLn $ "hChSf: " ++ showBytesHex hChSf
        putStrLn $ "masterSecret: " ++ showBytesHex masterSecret
        putStrLn $ "serverApplicationTrafficSecret0: " ++ showBytesHex serverApplicationTrafficSecret0
        putStrLn $ "clientApplicationTrafficSecret0: " ++ showBytesHex clientApplicationTrafficSecret0
        putStrLn "---- setTxState ctx usedHash usedCipher clientApplicationTrafficSecret0"
-}
        setTxState ctx usedHash usedCipher clientApplicationTrafficSecret0
        setRxState ctx usedHash usedCipher serverApplicationTrafficSecret0
        return masterSecret

    calcSharedKey = do
        serverKeyShare <- case extensionLookup extensionID_KeyShare exts >>= extensionDecode MsgTServerHello of
            Just (KeyShareServerHello ks) -> return ks
            _                             -> throwCore $ Error_Protocol ("key exchange not implemented", True, HandshakeFailure)
        usingHState ctx $ setTLS13Group $ keyShareEntryGroup serverKeyShare
        usingHState ctx getGroupPrivate >>= fromServerKeyShare serverKeyShare

    makeEarlySecret = do
        mEarlySecret <- usingHState ctx getTLS13MasterSecret
        case mEarlySecret of
          Nothing  -> return (hkdfExtract usedHash zero zero, False)
          Just sec -> case extensionLookup extensionID_PreSharedKey exts >>= extensionDecode MsgTServerHello of
            Nothing                          -> do
                putStrLn "PSK is not accepted by the server ... falling back to full handshake"
                return (hkdfExtract usedHash zero zero, False)
            Just (PreSharedKeyServerHello 0) -> putStrLn "PSK[0] is used" >> return (sec, True)
            Just _                           -> throwCore $ Error_Protocol ("psk out of range", True, IllegalParameter)

    recvEncryptedExtensions = do
        ee@(EncryptedExtensions13 eexts) <- recvHandshake13 ctx
        setALPN ctx eexts
        update ctx ee
        st <- usingHState ctx getTLS13RTT0Status
        if st == RTT0Sent then
            case extensionLookup extensionID_EarlyData eexts of
              Just _  -> do
                  usingHState ctx $ setTLS13RTT0Status RTT0Accepted
                  putStrLn "0RTT data is accepted"
                  return True
              Nothing -> do
                  usingHState ctx $ setTLS13RTT0Status RTT0Rejected
                  putStrLn "0RTT data is rejected"
                  return False
          else
            return False

    recvCertAndVerify = do
        cert <- recvHandshake13 ctx
        let Certificate13 _ cc@(CertificateChain certChain) _ = cert
        processCertificate13 cparams ctx cc
        update ctx cert
        pubkey <- case certChain of
                    [] -> throwCore $ Error_Protocol ("server certificate missing", True, HandshakeFailure)
                    c:_ -> return $ certPubKey $ getCertificate c
        certVerify <- recvHandshake13 ctx
        let CertVerify13 ss sig = certVerify
        hChSc <- transcriptHash ctx
        checkServerCertVerify ss sig pubkey hChSc
        update ctx certVerify

    recvFinished serverHandshakeTrafficSecret = do
        finished <- recvHandshake13 ctx
        hChSv <- transcriptHash ctx
        let verifyData' = makeVerifyData usedHash serverHandshakeTrafficSecret hChSv
        let Finished13 verifyData = finished
        when (verifyData' /= verifyData) $
            throwCore $ Error_Protocol ("cannot verify finished", True, HandshakeFailure)
        update ctx finished

    setResumptionSecret masterSecret = do
        hChCf <- transcriptHash ctx
        let resumptionMasterSecret = deriveSecret usedHash masterSecret "res master" hChCf
        usingHState ctx $ setTLS13MasterSecret $ Just resumptionMasterSecret

update' :: Context -> Handshake -> IO ()
update' ctx hs = usingHState ctx $ do
    updateHandshakeDigest encoded
    addHandshakeMessage encoded
  where
    encoded = encodeHandshake hs

update :: Context -> Handshake13 -> IO ()
update ctx hs = usingHState ctx $ do
    updateHandshakeDigest encoded
    addHandshakeMessage encoded
  where
    encoded = encodeHandshake13 hs

recvHandshake13 :: Context -> IO Handshake13
recvHandshake13 ctx = do
    msgs <- usingHState ctx getTLS13HandshakeMsgs
    case msgs of
        [] -> do
            epkt <- recvPacket13 ctx
            case epkt of
                Right (Handshake13 (h:hs)) -> do
                    usingHState ctx $ setTLS13HandshakeMsgs hs
                    return h
                x                          -> error $ show x
        h:hs -> do
            usingHState ctx $ setTLS13HandshakeMsgs hs
            return h

processCertificate13 :: ClientParams -> Context -> CertificateChain -> IO ()
processCertificate13 cparams ctx cc = do
    -- run certificate recv hook
    ctxWithHooks ctx (\hooks -> hookRecvCertificates hooks $ cc)
    -- then run certificate validation
    usage <- catchException (wrapCertificateChecks <$> checkCert) rejectOnException
    case usage of
        CertificateUsageAccept        -> return ()
        CertificateUsageReject reason -> certificateRejected reason
    return ()
  where shared = clientShared cparams
        checkCert = (onServerCertificate $ clientHooks cparams) (sharedCAStore shared)
                                                                (sharedValidationCache shared)
                                                                (clientServerIdentification cparams)
                                                                cc

setALPN :: Context -> [ExtensionRaw] -> IO ()
setALPN ctx exts = case extensionLookup extensionID_ApplicationLayerProtocolNegotiation exts >>= extensionDecode MsgTServerHello of
    Just (ApplicationLayerProtocolNegotiation [proto]) -> usingState_ ctx $ do
        mprotos <- getClientALPNSuggest
        case mprotos of
            Just protos -> when (elem proto protos) $ do
                setExtensionALPN True
                setNegotiatedProtocol proto
            _ -> return ()
    _ -> return ()
