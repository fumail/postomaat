# -*- coding: UTF-8 -*-
SQLALCHEMY_AVAILABLE=False
try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import scoped_session, sessionmaker
    SQLALCHEMY_AVAILABLE=True
except ImportError:
    pass


_sessmaker = None
_engines = {}


def get_session(connectstring, **kwargs):
    global SQLALCHEMY_AVAILABLE
    global _sessmaker
    global _engines

    if not SQLALCHEMY_AVAILABLE:
        raise Exception("sql extension not enabled")

    if connectstring in _engines:
        engine = _engines[connectstring]
    else:
        engine = create_engine(connectstring, pool_recycle=20)
        _engines[connectstring] = engine

    if _sessmaker == None:
        _sessmaker = sessionmaker(autoflush=True, autocommit=True, **kwargs)

    session = scoped_session(_sessmaker)
    session.configure(bind=engine)
    return session