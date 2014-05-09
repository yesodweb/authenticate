{-# LANGUAGE CPP                  #-}
{-# LANGUAGE FlexibleContexts     #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE UndecidableInstances #-}

module Web.Authenticate.OAuth.UnsafeIO where

import Prelude
import Control.Monad.Trans.Class (MonadTrans (..))
import Control.Monad.IO.Class (MonadIO (..))
import Control.Monad (liftM)
import Control.Monad.ST (ST)
#if __GLASGOW_HASKELL__ >= 704
import Control.Monad.ST.Unsafe (unsafeIOToST)
#else
import Control.Monad.ST (unsafeIOToST)
#endif

#if __GLASGOW_HASKELL__ >= 704
import qualified Control.Monad.ST.Lazy.Unsafe as LazyUnsafe
#else
import qualified Control.Monad.ST.Lazy as LazyUnsafe
#endif

import qualified Control.Monad.ST.Lazy as Lazy

class Monad m => MonadUnsafeIO m where
    unsafeLiftIO :: IO a -> m a

instance MonadUnsafeIO IO where
    unsafeLiftIO = id

instance MonadUnsafeIO (ST s) where
    unsafeLiftIO = unsafeIOToST

instance MonadUnsafeIO (Lazy.ST s) where
    unsafeLiftIO = LazyUnsafe.unsafeIOToST

instance (MonadTrans t, MonadUnsafeIO m, Monad (t m)) => MonadUnsafeIO (t m) where
    unsafeLiftIO = lift . unsafeLiftIO
