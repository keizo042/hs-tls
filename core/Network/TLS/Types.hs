-- |
-- Module      : Network.TLS.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Types
    ( Version(..)
    , SessionID
    , SessionData(..)
    , TLS13TicketInfo(..)
    , CipherID
    , CompressionID
    , Role(..)
    , invertRole
    , Direction(..)
--    , HostName
    ) where

import Data.ByteString (ByteString)
import Data.Word
import Network.TLS.Crypto.Types (Group)

type HostName = String

-- | Versions known to TLS
--
-- SSL2 is just defined, but this version is and will not be supported.
data Version = SSL2 | SSL3 | TLS10 | TLS11 | TLS12 | TLS13ID20 | TLS13 deriving (Show, Eq, Ord, Bounded)

-- | A session ID
type SessionID = ByteString

-- | Session data to resume
data SessionData = SessionData
    { sessionVersion     :: Version
    , sessionCipher      :: CipherID
    , sessionCompression :: CompressionID
    , sessionClientSNI   :: Maybe HostName
    , sessionSecret      :: ByteString
    , sessionGroup       :: Maybe Group
    , sessionTicketInfo  :: Maybe TLS13TicketInfo
    } deriving (Show,Eq)

data TLS13TicketInfo = TLS13TicketInfo
    { lifetime :: Word32 -- NewSessionTicket.ticket_lifetime in seconds
    , ageAdd   :: Word32 -- NewSessionTicket.ticket_age_add
    , txrxTime :: Word64 -- serverSendTime or clientReceiveTime in milliseconds
    } deriving (Show,Eq)

-- | Cipher identification
type CipherID = Word16

-- | Compression identification
type CompressionID = Word8

-- | Role
data Role = ClientRole | ServerRole
    deriving (Show,Eq)

-- | Direction
data Direction = Tx | Rx
    deriving (Show,Eq)

invertRole :: Role -> Role
invertRole ClientRole = ServerRole
invertRole ServerRole = ClientRole
