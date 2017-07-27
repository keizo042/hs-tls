{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Packet13 where

import Control.Applicative
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Packet
import Network.TLS.Wire
import Data.X509 (CertificateChainRaw(..), encodeCertificateChain, decodeCertificateChain)

encodeHandshakes13 :: [Handshake13] -> ByteString
encodeHandshakes13 hss = B.concat $ map encodeHandshake13 hss

encodeHandshake13 :: Handshake13 -> ByteString
encodeHandshake13 hdsk = pkt
  where
    !tp = typeOfHandshake13 hdsk
    !content = encodeHandshake13' hdsk
    !len = fromIntegral $ B.length content
    !header = encodeHandshakeHeader13 tp len
    !pkt = B.concat [header, content]

-- TLS 1.3 does not use "select (extensions_present)".
putExtensions :: [ExtensionRaw] -> Put
putExtensions es = putOpaque16 (runPut $ mapM_ putExtension es)

encodeHandshake13' :: Handshake13 -> ByteString
encodeHandshake13' (HelloRetryRequest13 ver exts) = runPut $ do
    putVersion' ver
    putExtensions exts
encodeHandshake13' (ServerHello13 ver random cipherId exts) = runPut $ do
    putVersion' ver
    putServerRandom32 random
    putWord16 cipherId
    putExtensions exts
encodeHandshake13' (EncryptedExtensions13 exts) = runPut $ putExtensions exts
encodeHandshake13' (Certificate13 reqctx cc ess) = runPut $ do
    putOpaque8 reqctx
    putOpaque24 (runPut $ mapM_ putCert $ zip certs ess)
  where
    CertificateChainRaw certs = encodeCertificateChain cc
    putCert (certRaw,exts) = do
        putOpaque24 certRaw
        putExtensions exts
encodeHandshake13' (CertVerify13 hs signature) = runPut $ do
    putSignatureHashAlgorithm hs
    putOpaque16 signature
encodeHandshake13' (Finished13 dat) = runPut $ putBytes dat
encodeHandshake13' (NewSessionTicket13 life ageadd ticket exts) = runPut $ do
    putWord32 life
    putWord32 ageadd
    putOpaque16 ticket
    putExtensions exts
encodeHandshake13' _ = error "encodeHandshake13'"

encodeHandshakeHeader13 :: HandshakeType13 -> Int -> ByteString
encodeHandshakeHeader13 ty len = runPut $ do
    putWord8 (valOfType ty)
    putWord24 len


{- decode and encode HANDSHAKE -}
getHandshakeType13 :: Get HandshakeType13
getHandshakeType13 = do
    ty <- getWord8
    case valToType ty of
        Nothing -> fail ("invalid handshake type: " ++ show ty)
        Just t  -> return t

decodeHandshakeRecord13 :: ByteString -> GetResult (HandshakeType13, ByteString)
decodeHandshakeRecord13 = runGet "handshake-record" $ do
    ty      <- getHandshakeType13
    content <- getOpaque24
    return (ty, content)

decodeHandshake13 :: HandshakeType13 -> ByteString -> Either TLSError Handshake13
decodeHandshake13 ty = runGetErr ("handshake[" ++ show ty ++ "]") $ case ty of
    HandshakeType_Finished13            -> decodeFinished13
    HandshakeType_EncryptedExtensions13 -> decodeEncryptedExtensions13
    HandshakeType_Certificate13         -> decodeCertificate13
    HandshakeType_CertVerify13          -> decodeCertVerify13
    HandshakeType_NewSessionTicket13    -> decodeNewSessionTicket13
    _x                                  -> error $ "decodeHandshake13 " ++ show _x

decodeFinished13 :: Get Handshake13
decodeFinished13 = Finished13 <$> (remaining >>= getBytes)

decodeEncryptedExtensions13 :: Get Handshake13
decodeEncryptedExtensions13 = EncryptedExtensions13 <$> do
    len <- fromIntegral <$> getWord16
    getExtensions len

decodeCertificate13 :: Get Handshake13
decodeCertificate13 = do
    reqctx <- getOpaque8
    len <- fromIntegral <$> getWord24
    (certRaws, ess) <- unzip <$> getList len getCert
    let Right certs = decodeCertificateChain $ CertificateChainRaw certRaws -- fixme
    return $ Certificate13 reqctx certs ess
  where
    getCert = do
        l <- fromIntegral <$> getWord24
        cert <- getBytes l
        len <- fromIntegral <$> getWord16
        exts <- getExtensions len
        return (3 + l + 2 + len, (cert, exts))

decodeCertVerify13 :: Get Handshake13
decodeCertVerify13 = do
    hs <- getSignatureHashAlgorithm
    signature <- getOpaque16
    return $ CertVerify13 hs signature

decodeNewSessionTicket13 :: Get Handshake13
decodeNewSessionTicket13 = do
    life <- getWord32
    ageadd <- getWord32
    ticket <- getOpaque16
    len <- fromIntegral <$> getWord16
    exts <- getExtensions len
    return $ NewSessionTicket13 life ageadd ticket exts
