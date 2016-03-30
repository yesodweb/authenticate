{-# LANGUAGE CPP, DeriveDataTypeable, FlexibleContexts, MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings, StandaloneDeriving                            #-}
module Web.Authenticate.OAuth
    ( -- * Data types
      OAuth, def, newOAuth, oauthServerName, oauthRequestUri, oauthAccessTokenUri,
      oauthAuthorizeUri, oauthSignatureMethod, oauthConsumerKey,
      oauthConsumerSecret, oauthCallback, oauthRealm, oauthVersion,
      OAuthVersion(..), SignMethod(..), Credential(..), OAuthException(..),
      -- ** Access token request
      AccessTokenRequest,
      defaultAccessTokenRequest,
      accessTokenAddAuth,
      accessTokenRequestHook,
      accessTokenOAuth,
      accessTokenTemporaryCredential,
      accessTokenManager,
      -- * Operations for credentials
      newCredential, emptyCredential, insert, delete, inserts, injectVerifier,
      -- * Signature
      signOAuth, genSign, checkOAuth,
      -- * Url & operation for authentication
      -- ** Temporary credentials
      getTemporaryCredential, getTemporaryCredentialWithScope,
      getTemporaryCredentialProxy, getTemporaryCredential',
      -- ** Authorization URL
      authorizeUrl, authorizeUrl',
      -- ** Attaching auth to requests
      addAuthBody,
      -- ** Finishing authentication
      getAccessToken,
      getAccessTokenProxy,
      getTokenCredential,
      getTokenCredentialProxy,
      getAccessToken',
      getAccessTokenWith,
      -- * Utility Methods
      paramEncode, addScope, addMaybeProxy
    ) where

import           Blaze.ByteString.Builder     (toByteString)
import           Control.Exception
import           Control.Arrow                (second)
import           Control.Monad
import           Control.Monad.IO.Class       (MonadIO, liftIO)
import           Control.Monad.Trans.Except
import           Crypto.Types.PubKey.RSA      (PrivateKey (..)) -- , PublicKey (..)
import           Data.ByteString.Base64
import qualified Data.ByteString.Char8        as BS
import qualified Data.ByteString.Lazy.Char8   as BSL
import           Data.Char
import           Data.Default
import           Data.Digest.Pure.SHA
import qualified Data.IORef                   as I
import           Data.List                    as List (sort, find)
import           Data.Maybe
import           Data.Time
import           Network.HTTP.Client
import           Network.HTTP.Types           (SimpleQuery, parseSimpleQuery)
import           Network.HTTP.Types           (Header)
import           Network.HTTP.Types           (renderSimpleQuery, status200)
import           Numeric
import           System.Random
#if MIN_VERSION_base(4,7,0)
import Data.Data hiding (Proxy (..))
#else
import Data.Data
#endif
import Codec.Crypto.RSA (rsassa_pkcs1_v1_5_sign, hashSHA1)


----------------------------------------------------------------------
-- Data types


-- | Data type for OAuth client (consumer).
--
-- The constructor for this data type is not exposed.
-- Instead, you should use the 'def' method or 'newOAuth' function to retrieve a default instance,
-- and then use the records below to make modifications.
-- This approach allows us to add configuration options without breaking backwards compatibility.
data OAuth = OAuth { oauthServerName      :: String -- ^ Service name (default: @\"\"@)
                   , oauthRequestUri      :: String
                   -- ^ URI to request temporary credential (default: @\"\"@).
                   --   You MUST specify if you use 'getTemporaryCredential'', 'getTemporaryCredentialProxy'
                   --   or 'getTemporaryCredential'; otherwise you can just leave this empty.
                   , oauthAccessTokenUri  :: String
                   -- ^ Uri to obtain access token (default: @\"\"@).
                   --   You MUST specify if you use 'getAcessToken' or 'getAccessToken'' or 'getAccessTokenWith';
                   --   otherwise you can just leave this empty.
                   , oauthAuthorizeUri    :: String
                   -- ^ Uri to authorize (default: @\"\"@).
                   --   You MUST specify if you use 'authorizeUrl' or 'authorizeZUrl'';
                   --   otherwise you can just leave this empty.
                   , oauthSignatureMethod :: SignMethod
                   -- ^ Signature Method (default: 'HMACSHA1')
                   , oauthConsumerKey     :: BS.ByteString
                   -- ^ Consumer key (You MUST specify)
                   , oauthConsumerSecret  :: BS.ByteString
                   -- ^ Consumer Secret (You MUST specify)
                   , oauthCallback        :: Maybe BS.ByteString
                   -- ^ Callback uri to redirect after authentication (default: @Nothing@)
                   , oauthRealm           :: Maybe BS.ByteString
                   -- ^ Optional authorization realm (default: @Nothing@)
                   , oauthVersion         :: OAuthVersion
                   -- ^ OAuth spec version (default: 'OAuth10a')
                   } deriving (Show, Eq, Read, Data, Typeable)


data OAuthVersion = OAuth10     -- ^ OAuth protocol ver 1.0 (no oauth_verifier; differs from RFC 5849).
                  | OAuth10a    -- ^ OAuth protocol ver 1.0a. This corresponds to community's 1.0a spec and RFC 5849.
                    deriving (Show, Eq, Enum, Ord, Data, Typeable, Read)


-- | Default value for OAuth datatype.
-- You must specify at least oauthServerName, URIs and Tokens.
newOAuth :: OAuth
newOAuth = OAuth { oauthSignatureMethod = HMACSHA1
                 , oauthCallback = Nothing
                 , oauthRealm    = Nothing
                 , oauthServerName = ""
                 , oauthRequestUri = ""
                 , oauthAccessTokenUri = ""
                 , oauthAuthorizeUri = ""
                 , oauthConsumerKey = error "You MUST specify oauthConsumerKey parameter."
                 , oauthConsumerSecret = error "You MUST specify oauthConsumerSecret parameter."
                 , oauthVersion = OAuth10a
                 }

instance Default OAuth where
  def = newOAuth


-- | Data type for signature method.
data SignMethod = PLAINTEXT
                | HMACSHA1
                | RSASHA1 PrivateKey
                  deriving (Show, Eq, Read, Data, Typeable)


newtype OAuthException = OAuthException String
                      deriving (Show, Eq, Data, Typeable)

instance Exception OAuthException


-- | Data type for getAccessTokenWith method.
--
-- You can create values of this type using 'defaultAccessTokenRequest'.
--
-- Since 1.5.1
data AccessTokenRequest = AccessTokenRequest {
    accessTokenAddAuth :: (BS.ByteString -> Credential -> Request -> Request)
    -- ^ add auth hook.
    --
    -- Default: addAuthHeader
    --
    -- Since 1.5.1
  , accessTokenRequestHook :: (Request -> Request)
    -- ^ Request Hook.
    --
    -- Default: @id@
    --
    -- Since 1.5.1
  , accessTokenOAuth :: OAuth
    -- ^ OAuth Application
    --
    -- Since 1.5.1
  , accessTokenTemporaryCredential :: Credential
    -- ^ Temporary Credential (with oauth_verifier if >= 1.0a)
    --
    -- Since 1.5.1
  , accessTokenManager :: Manager
    -- ^ Manager
    --
    -- Since 1.5.1
  }

-- | Create a value of type 'AccessTokenRequest' with default values filled in.
--
-- Note that this is a settings type. More information on usage can be found
-- at: <http://www.yesodweb.com/book/settings-types>.
--
-- Since 1.5.1
defaultAccessTokenRequest :: OAuth -> Credential -> Manager -> AccessTokenRequest
defaultAccessTokenRequest oauth cred man = AccessTokenRequest
    { accessTokenAddAuth = addAuthHeader
    , accessTokenRequestHook = id
    , accessTokenOAuth = oauth
    , accessTokenTemporaryCredential = cred
    , accessTokenManager = man
    }

----------------------------------------------------------------------
-- Credentials


-- | Data type for redential.
newtype Credential = Credential -- we can easily change it back to "data" later if needed, right?
    { unCredential :: [(BS.ByteString, BS.ByteString)] }
    deriving (Show, Eq, Ord, Read, Data, Typeable)


-- | Convenient function to create 'Credential' with OAuth Token and Token Secret.
newCredential :: BS.ByteString -- ^ value for oauth_token
              -> BS.ByteString -- ^ value for oauth_token_secret
              -> Credential
newCredential tok sec = Credential [("oauth_token", tok), ("oauth_token_secret", sec)]


-- | Empty credential.
emptyCredential :: Credential
emptyCredential = Credential []


-- | Insert an oauth parameter into given 'Credential'.
insert :: BS.ByteString -- ^ Parameter Name
       -> BS.ByteString -- ^ Value
       -> Credential    -- ^ Credential
       -> Credential    -- ^ Result
insert k v = Credential . insertMap k v . unCredential


-- | Convenient method for inserting multiple parameters into credential.
inserts :: [(BS.ByteString, BS.ByteString)] -> Credential -> Credential
inserts = flip $ foldr (uncurry insert)


-- | Remove an oauth parameter for key from given 'Credential'.
delete :: BS.ByteString -- ^ Parameter name
       -> Credential    -- ^ Credential
       -> Credential    -- ^ Result
delete key = Credential . deleteMap key . unCredential


-- | Insert @oauth-verifier@ on a 'Credential'.
injectVerifier :: BS.ByteString -> Credential -> Credential
injectVerifier = insert "oauth_verifier"


----------------------------------------------------------------------
-- Signature

-- | Add OAuth headers & sign to 'Request'.
signOAuth :: MonadIO m
          => OAuth              -- ^ OAuth Application
          -> Credential         -- ^ Credential
          -> Request            -- ^ Original Request
          -> m Request          -- ^ Signed OAuth Request
signOAuth oa crd req = signOAuth' oa crd True addAuthHeader req

-- | More flexible signOAuth
signOAuth' :: MonadIO m
          => OAuth              -- ^ OAuth Application
          -> Credential         -- ^ Credential
          -> Bool               -- ^ whether to insert oauth_body_hash or not
          -> (BS.ByteString -> Credential -> Request -> Request) -- ^ signature style
          -> Request            -- ^ Original Request
          -> m Request          -- ^ Signed OAuth Request
signOAuth' oa crd withHash add_auth req = do
  crd' <- addTimeStamp =<< addNonce crd
  mhash <- moauth_body_hash
  let tok = addHashToCred mhash $ injectOAuthToCred oa crd'
  sign <- genSign oa tok req
  let prefix = case oauthRealm oa of
        Nothing -> "OAuth "
        Just v  -> "OAuth realm=\"" `BS.append` v `BS.append` "\","
  return $ add_auth prefix
                    (insert "oauth_signature" sign tok)
                    req
  where -- adding extension https://oauth.googlecode.com/svn/spec/ext/body_hash/1.0/oauth-bodyhash.html
    moauth_body_hash = if not withHash || isBodyFormEncoded (requestHeaders req)
          then return Nothing
          else (Just
             . encode
             . BSL.toStrict
             . bytestringDigest
             . sha1
             . BSL.fromStrict) `liftM` loadBodyBS req
    -- encodeHash (Just h) = "oauth_body_hash=\"" `BS.append` paramEncode h `BS.append` "\","
    -- encodeHash Nothing  = ""
    addHashToCred (Just h) = insert "oauth_body_hash" h
    addHashToCred Nothing  = id


-- | Generate OAuth signature.  Used by 'signOAuth'.
genSign :: MonadIO m => OAuth -> Credential -> Request -> m BS.ByteString
genSign oa tok req =
  case oauthSignatureMethod oa of
    HMACSHA1 -> do
      text <- getBaseString tok req
      let key  = BS.intercalate "&" $ map paramEncode [oauthConsumerSecret oa, tokenSecret tok]
      return $ encode $ toStrict $ bytestringDigest $ hmacSha1 (fromStrict key) text
    PLAINTEXT ->
      return $ BS.intercalate "&" $ map paramEncode [oauthConsumerSecret oa, tokenSecret tok]
    RSASHA1 pr ->
      liftM (encode . toStrict . rsassa_pkcs1_v1_5_sign hashSHA1 pr) (getBaseString tok req)

-- | Test existing OAuth signature.
--   Since 1.5.2
checkOAuth :: MonadIO m
           => OAuth -> Credential -> Request
           -> ExceptT OAuthException m Request
checkOAuth oa crd req = if isBodyFormEncoded origHeaders then checkOAuthB oa crd req else do
  case mosig of
    Nothing -> throwE $ OAuthException "oauth_signature parameter not found"
    Just osig -> do
      mhash <- moauth_body_hash
      case (\oh nh -> oh == paramEncode nh) `liftM` moauth_body_hash_orig `ap` mhash of
        Just False -> throwE $ OAuthException "Failed test of oauth_body_hash"
        _ -> let tok = addHashToCred mhash . injectOAuthToCred oa $ inserts (remParams authParams) crd
             in genSign oa tok req
                  {requestHeaders = catMaybes [mtypeHeader]}
                >>= \nsig -> if osig == paramEncode nsig
                             then return req
                             else throwE $ OAuthException "Failed test of oauth_signature"
  where
    origHeaders = requestHeaders req
    mauthHeader = List.find ( ("Authorization" ==) . fst) $ origHeaders
    mtypeHeader = List.find ( ("Content-Type" ==) . fst) $ origHeaders
    authParams = (map parseParam . BS.split ',' . BS.drop 6 . snd) `liftM` mauthHeader
    remParams Nothing = []
    remParams (Just ms) = filter ( not . flip elem
                                            ("realm" : "oauth_signature" : map fst (unCredential crd))
                                       . fst) ms
    mosig = fmap snd . join $ List.find (("oauth_signature" ==) . fst) `liftM` authParams
    parseParam = second (BS.takeWhile ('"' /=) . BS.drop 1 . BS.dropWhile ('"' /=))
               . splitEq . BS.dropWhile (' ' ==)
    splitEq s = case BS.elemIndex '=' s of
                  Nothing -> (s,"")
                  Just i -> BS.splitAt i s
    moauth_body_hash_orig = join $ (fmap snd . List.find ( ("oauth_body_hash" ==) . fst)) `liftM` authParams
    moauth_body_hash = if moauth_body_hash_orig == Nothing
          then return Nothing
          else (Just
             . encode
             . BSL.toStrict
             . bytestringDigest
             . sha1
             . BSL.fromStrict) `liftM` loadBodyBS req
    addHashToCred (Just h) = insert "oauth_body_hash" h
    addHashToCred Nothing  = id

checkOAuthB :: MonadIO m
            => OAuth -> Credential -> Request
            -> ExceptT OAuthException m Request
checkOAuthB oa crd req0 = do
  (mosig, reqBody) <- getSig `liftM` loadBodyBS req0
  let req = req0 {requestBody = RequestBodyBS reqBody}
  case mosig of
    "" -> throwE $ OAuthException "oauth_signature parameter not found"
    osig -> do
          nsig <- genSign oa crd req
          if osig == paramEncode nsig
            then return req0
            else throwE $ OAuthException "Failed test of oauth_signature"
  where
    getSig b = let (h1 , r ) = BS.breakSubstring "&oauth_signature=" b
                   (sig, h2) = BS.breakSubstring "&" $ BS.drop 17 r
               in (sig, h1 `BS.append` h2)



----------------------------------------------------------------------
-- Temporary credentails


-- | Get temporary credential for requesting acces token.
getTemporaryCredential :: MonadIO m
                       => OAuth         -- ^ OAuth Application
                       -> Manager
                       -> m Credential -- ^ Temporary Credential (Request Token & Secret).
getTemporaryCredential = getTemporaryCredential' id


-- | Get temporary credential for requesting access token with Scope parameter.
getTemporaryCredentialWithScope :: MonadIO m
                                => BS.ByteString -- ^ Scope parameter string
                                -> OAuth         -- ^ OAuth Application
                                -> Manager
                                -> m Credential -- ^ Temporay Credential (Request Token & Secret).
getTemporaryCredentialWithScope bs = getTemporaryCredential' (addScope bs)


-- | Get temporary credential for requesting access token via the proxy.
getTemporaryCredentialProxy :: MonadIO m
                            => Maybe Proxy   -- ^ Proxy
                            -> OAuth         -- ^ OAuth Application
                            -> Manager
                            -> m Credential -- ^ Temporary Credential (Request Token & Secret).
getTemporaryCredentialProxy p oa m = getTemporaryCredential' (addMaybeProxy p) oa m


getTemporaryCredential' :: MonadIO m
                        => (Request -> Request)       -- ^ Request Hook
                        -> OAuth                      -- ^ OAuth Application
                        -> Manager
                        -> m Credential    -- ^ Temporary Credential (Request Token & Secret).
getTemporaryCredential' hook oa manager = do
  let req = fromJust $ parseUrl $ oauthRequestUri oa
      crd = maybe id (insert "oauth_callback") (oauthCallback oa) $ emptyCredential
  req' <- signOAuth' oa crd False addAuthHeader $ hook (req { method = "POST" })
  rsp <- liftIO $ httpLbs req' manager
  if responseStatus rsp == status200
    then do
      let dic = parseSimpleQuery . toStrict . responseBody $ rsp
      return $ Credential dic
    else liftIO . throwIO . OAuthException
            $ "Gaining OAuth Temporary Credential Failed: " ++ BSL.unpack (responseBody rsp)


----------------------------------------------------------------------
-- Authorization URL


-- | URL to obtain OAuth verifier.
authorizeUrl :: OAuth           -- ^ OAuth Application
             -> Credential      -- ^ Temporary Credential (Request Token & Secret)
             -> String          -- ^ URL to authorize
authorizeUrl = authorizeUrl' $ \oa -> const [("oauth_consumer_key", oauthConsumerKey oa)]


-- | Convert OAuth and Credential to URL to authorize.
--   This takes function to choice parameter to pass to the server other than
--   /oauth_callback/ or /oauth_token/.
authorizeUrl' :: (OAuth -> Credential -> SimpleQuery)
              -> OAuth           -- ^ OAuth Application
              -> Credential      -- ^ Temporary Credential (Request Token & Secret)
              -> String          -- ^ URL to authorize
authorizeUrl' f oa cr = oauthAuthorizeUri oa ++ BS.unpack (renderSimpleQuery True queries)
  where fixed   = ("oauth_token", token cr):f oa cr
        queries =
          case oauthCallback oa of
            Nothing       -> fixed
            Just callback -> ("oauth_callback", callback):fixed


----------------------------------------------------------------------
-- Finishing authentication


-- | Get Access token.
getAccessToken, getTokenCredential
               :: MonadIO m
               => OAuth         -- ^ OAuth Application
               -> Credential    -- ^ Temporary Credential (with oauth_verifier if >= 1.0a)
               -> Manager
               -> m Credential -- ^ Token Credential (Access Token & Secret)
getAccessToken = getAccessToken' id


-- | Get Access token via the proxy.
getAccessTokenProxy, getTokenCredentialProxy
               :: MonadIO m
               => Maybe Proxy   -- ^ Proxy
               -> OAuth         -- ^ OAuth Application
               -> Credential    -- ^ Temporary Credential (with oauth_verifier if >= 1.0a)
               -> Manager
               -> m Credential -- ^ Token Credential (Access Token & Secret)
getAccessTokenProxy p = getAccessToken' $ addMaybeProxy p

getAccessToken' :: MonadIO m
                => (Request -> Request)       -- ^ Request Hook
                -> OAuth                      -- ^ OAuth Application
                -> Credential                 -- ^ Temporary Credential (with oauth_verifier if >= 1.0a)
                -> Manager
                -> m Credential     -- ^ Token Credential (Access Token & Secret)
getAccessToken' hook oauth cr manager = do
    maybe_access_token <- getAccessTokenWith AccessTokenRequest
            { accessTokenAddAuth = addAuthHeader
            , accessTokenRequestHook = hook
            , accessTokenOAuth = oauth
            , accessTokenTemporaryCredential = cr
            , accessTokenManager = manager
            }
    case maybe_access_token of
        Left error_response -> liftIO . throwIO . OAuthException
                            $ "Gaining OAuth Token Credential Failed: "
                                    ++ BSL.unpack (responseBody error_response)
        Right access_token -> return access_token

getAccessTokenWith :: MonadIO m
                => AccessTokenRequest -- ^ extensible parameters
                -> m (Either (Response BSL.ByteString) Credential
                     )  -- ^ Token Credential (Access Token & Secret) or the conduit response on failures
getAccessTokenWith params = do
      let req = hook (fromJust $ parseUrl $ oauthAccessTokenUri oa) { method = "POST" }
      rsp <- liftIO $ flip httpLbs manager
                    =<< signOAuth' oa (if oauthVersion oa == OAuth10
                                       then delete "oauth_verifier" cr
                                       else cr) False add_auth req
      if responseStatus rsp == status200
        then do
          let dic = parseSimpleQuery . toStrict . responseBody $ rsp
          return $ Right $ Credential dic
        else
          return $ Left rsp
    where
      add_auth = accessTokenAddAuth params
      hook = accessTokenRequestHook params
      oa = accessTokenOAuth params
      cr = accessTokenTemporaryCredential params
      manager = accessTokenManager params

getTokenCredential = getAccessToken
getTokenCredentialProxy = getAccessTokenProxy


baseTime :: UTCTime
baseTime = UTCTime day 0
  where
    day = ModifiedJulianDay 40587

showSigMtd :: SignMethod -> BS.ByteString
showSigMtd PLAINTEXT = "PLAINTEXT"
showSigMtd HMACSHA1  = "HMAC-SHA1"
showSigMtd (RSASHA1 _) = "RSA-SHA1"

addNonce :: MonadIO m => Credential -> m Credential
addNonce cred = do
  nonce <- liftIO $ replicateM 10 (randomRIO ('a','z')) -- FIXME very inefficient
  return $ insert "oauth_nonce" (BS.pack nonce) cred

addTimeStamp :: MonadIO m => Credential -> m Credential
addTimeStamp cred = do
  stamp <- (floor . (`diffUTCTime` baseTime)) `liftM` liftIO getCurrentTime
  return $ insert "oauth_timestamp" (BS.pack $ show (stamp :: Integer)) cred

injectOAuthToCred :: OAuth -> Credential -> Credential
injectOAuthToCred oa cred =
    inserts [ ("oauth_signature_method", showSigMtd $ oauthSignatureMethod oa)
            , ("oauth_consumer_key", oauthConsumerKey oa)
            , ("oauth_version", "1.0")
            ] cred


-- | Place the authentication information in a URL encoded body instead of the Authorization header.
--
-- Note that the first parameter is used for realm in addAuthHeader, and this
-- function needs the same type. The parameter, however, is unused.
--
-- Since 1.5.1
addAuthBody :: a -> Credential -> Request -> Request
addAuthBody _ (Credential cred) req = urlEncodedBody (filterCreds cred) req

addAuthHeader :: BS.ByteString -> Credential -> Request -> Request
addAuthHeader prefix (Credential cred) req =
  req { requestHeaders = insertMap "Authorization" (renderAuthHeader prefix cred) $ requestHeaders req }

renderAuthHeader :: BS.ByteString -> [(BS.ByteString, BS.ByteString)] -> BS.ByteString
renderAuthHeader prefix = (prefix `BS.append`)
                        . BS.intercalate ","
                        . map (\(a,b) -> BS.concat [paramEncode a, "=\"",  paramEncode b, "\""])
                        . filterCreds

filterCreds :: [(BS.ByteString, BS.ByteString)] -> [(BS.ByteString, BS.ByteString)]
-- as per http://oauth.net/core/1.0a  -- 9.1.1.  Normalize Request Parameters
-- everything except "realm" parameter should be encoded
-- 6.1.1, 6.1.2, 6.2.1,  6.3.2 and 7 allow encoding anything in the authorization parameters
-- 6.2.3 is only limited to oauth_token and oauth_verifier (although query params are allowed)
-- 6.3.1 does not allow specifing other params, so no need to filter them (it is an error anyway)
filterCreds = filter (not . flip elem ["realm", "oauth_token_secret"] . fst )
--filterCreds = filter ((`elem` [ "oauth_consumer_key"
--                              , "oauth_token"
--                              , "oauth_signature"
--                              , "oauth_signature_method"
--                              , "oauth_timestamp"
--                              , "oauth_nonce"
--                              , "oauth_verifier"
--                              , "oauth_version"
--                              , "oauth_callback"
--                              ] ) . fst )


getBaseString :: MonadIO m => Credential -> Request -> m BSL.ByteString
getBaseString tok req = do
  let bsMtd  = BS.map toUpper $ method req
      isHttps = secure req
      scheme = if isHttps then "https" else "http"
      bsPort = if (isHttps && port req /= 443) || (not isHttps && port req /= 80)
                 then ':' `BS.cons` BS.pack (show $ port req) else ""
      bsURI = BS.concat [scheme, "://", host req, bsPort, path req]
      bsQuery = parseSimpleQuery $ queryString req
  bsBodyQ <- if isBodyFormEncoded $ requestHeaders req
                  then liftM parseSimpleQuery $ loadBodyBS req
                  else return []
  let bsAuthParams = filterCreds $ unCredential tok
      allParams = bsQuery++bsBodyQ++bsAuthParams
      bsParams = BS.intercalate "&" $ map (\(a,b)->BS.concat[a,"=",b]) $ sort
                   $ map (\(a,b) -> (paramEncode a,paramEncode b)) allParams
  -- parameter encoding method in OAuth is slight different from ordinary one.
  -- So this is OK.
  return . BSL.fromStrict $ BS.intercalate "&" $ map paramEncode [bsMtd, bsURI, bsParams]


----------------------------------------------------------------------
-- Utilities

-- | Encode a string using the percent encoding method for OAuth.
paramEncode :: BS.ByteString -> BS.ByteString
paramEncode = BS.concatMap escape
  where
    escape c | isAscii c && (isAlpha c || isDigit c || c `elem` ("-._~" :: String)) = BS.singleton c
             | otherwise = let num = map toUpper $ showHex (ord c) ""
                               oct = '%' : replicate (2 - length num) '0' ++ num
                           in BS.pack oct


addScope :: BS.ByteString -> Request -> Request
addScope scope req | BS.null scope = req
                   | otherwise     = urlEncodedBody [("scope", scope)] req


token, tokenSecret :: Credential -> BS.ByteString
token = fromMaybe "" . lookup "oauth_token" . unCredential
tokenSecret = fromMaybe "" . lookup "oauth_token_secret" . unCredential


addMaybeProxy :: Maybe Proxy -> Request -> Request
addMaybeProxy p req = req { proxy = p }


insertMap :: Eq a => a -> b -> [(a,b)] -> [(a,b)]
insertMap key val = ((key,val):) . filter ((/=key).fst)

deleteMap :: Eq a => a -> [(a,b)] -> [(a,b)]
deleteMap k = filter ((/=k).fst)


toStrict :: BSL.ByteString -> BS.ByteString
toStrict = BS.concat . BSL.toChunks

fromStrict :: BS.ByteString -> BSL.ByteString
fromStrict = BSL.fromChunks . return


loadBodyBS :: MonadIO m => Request -> m BS.ByteString
loadBodyBS = toBS . requestBody

toBS :: MonadIO m => RequestBody -> m BS.ByteString
toBS (RequestBodyLBS l) = return $ toStrict l
toBS (RequestBodyBS s) = return s
toBS (RequestBodyBuilder _ b) = return $ toByteString b
toBS (RequestBodyStream _ givesPopper) = toBS' givesPopper
toBS (RequestBodyStreamChunked givesPopper) = toBS' givesPopper

toBS' :: MonadIO m => GivesPopper () -> m BS.ByteString
toBS' gp = liftIO $ do
    ref <- I.newIORef BS.empty
    gp (go ref)
    I.readIORef ref
  where
    go ref popper =
        loop id
      where
        loop front = do
            bs <- popper
            if BS.null bs
                then I.writeIORef ref $ BS.concat $ front []
                else loop (front . (bs:))


isBodyFormEncoded :: [Header] -> Bool
isBodyFormEncoded = maybe False (=="application/x-www-form-urlencoded") . lookup "Content-Type"
